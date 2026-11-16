// Connected Detector Vault (GTK3 + libusb): no key registered opens the database, otherwise lockscreen until a key is plugged in
// Build: gcc main_vault.c -o connected_detector_vault $(pkg-config --cflags --libs gtk+-3.0 libusb-1.0) | Run: ./connected_detector_vault [database_file]

#include <gtk/gtk.h>
#include <libusb.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define MAX_DEVICES      100
#define MAX_KEYS         8
#define STR_LEN          128
#define PHYS_LEN         64
#define HASH_LEN         65  // 64 hex + NUL
#define DB_FILE_DEFAULT  "known_devices.txt"
#define SCAN_EXISTING    1  // 1 = also list devices already plugged in at startup
#define UNKNOWN_NAME     "Unknown device"

typedef struct {
    uint16_t vid;
    uint16_t pid;
    char vendor[STR_LEN];
    char product[STR_LEN];
    char physical[PHYS_LEN];
} DeviceRecord;

typedef struct {
    char hash[HASH_LEN];
    char label[STR_LEN];
} KeyRecord;

static DeviceRecord db[MAX_DEVICES];
static int db_count = 0;
static const char *db_path = DB_FILE_DEFAULT;

static KeyRecord keys[MAX_KEYS];
static int key_count = 0;
static char key_salt[40] = "";
static char *key_path = NULL;
static gboolean locked = FALSE;

static void sanitize(char *s)
{
    for (; *s; s++)
        if (*s == '\t' || *s == '\n' || *s == '\r')
            *s = ' ';
}

static void copy_str(char *dst, size_t size, const char *src)
{
    strncpy(dst, src, size - 1);
    dst[size - 1] = '\0';
    sanitize(dst);
}

static DeviceRecord *find_record(uint16_t vid, uint16_t pid)
{
    for (int i = 0; i < db_count; i++)
        if (db[i].vid == vid && db[i].pid == pid)
            return &db[i];
    return NULL;
}

static DeviceRecord *upsert_record(uint16_t vid, uint16_t pid, const char *vendor,
                                   const char *product, const char *physical)
{
    DeviceRecord *r = find_record(vid, pid);
    if (!r) {
        if (db_count >= MAX_DEVICES)
            return NULL;
        r = &db[db_count++];
        memset(r, 0, sizeof *r);
        r->vid = vid;
        r->pid = pid;
    }
    if (vendor && vendor[0])   copy_str(r->vendor,  sizeof r->vendor,  vendor);
    if (product && product[0]) copy_str(r->product, sizeof r->product, product);
    copy_str(r->physical, sizeof r->physical, physical);
    return r;
}

static void remove_record(uint16_t vid, uint16_t pid)
{
    for (int i = 0; i < db_count; i++) {
        if (db[i].vid == vid && db[i].pid == pid) {
            memmove(&db[i], &db[i + 1], (db_count - i - 1) * sizeof db[0]);
            db_count--;
            return;
        }
    }
}

// Line format: VID<TAB>PID<TAB>vendor<TAB>product<TAB>physical
static void load_db(void)
{
    FILE *f = fopen(db_path, "r");
    if (!f)
        return;

    char line[512];
    while (db_count < MAX_DEVICES && fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '#' || line[0] == '\0')
            continue;

        char *fields[5];
        int n = 0;
        char *p = line;
        while (n < 5) {
            fields[n++] = p;
            char *tab = strchr(p, '\t');
            if (!tab) break;
            *tab = '\0';
            p = tab + 1;
        }
        if (n < 5)
            continue;

        DeviceRecord *r = &db[db_count++];
        memset(r, 0, sizeof *r);
        r->vid = (uint16_t)strtoul(fields[0], NULL, 16);
        r->pid = (uint16_t)strtoul(fields[1], NULL, 16);
        copy_str(r->vendor,   sizeof r->vendor,   fields[2]);
        copy_str(r->product,  sizeof r->product,  fields[3]);
        copy_str(r->physical, sizeof r->physical, fields[4]);
    }
    fclose(f);
}

static int save_db(void)
{
    FILE *f = fopen(db_path, "w");
    if (!f) {
        g_printerr("Gagal menulis '%s': %s\n", db_path, g_strerror(errno));
        return -1;
    }
    fprintf(f, "# VID\tPID\tVendor\tProduct\tPhysical\n");
    for (int i = 0; i < db_count; i++)
        fprintf(f, "%04x\t%04x\t%s\t%s\t%s\n",
                db[i].vid, db[i].pid, db[i].vendor, db[i].product, db[i].physical);
    fclose(f);
    return 0;
}

static void gen_salt(void)
{
    guint8 raw[16];
    gboolean ok = FALSE;
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        ok = fread(raw, 1, sizeof raw, f) == sizeof raw;
        fclose(f);
    }
    if (!ok)
        for (int i = 0; i < 16; i++)
            raw[i] = (guint8)g_random_int_range(0, 256);

    for (int i = 0; i < 16; i++)
        snprintf(key_salt + i * 2, 3, "%02x", raw[i]);
}

// SHA256(salt|vid|pid|serial)
static void key_hash(uint16_t vid, uint16_t pid, const char *serial, char *out)
{
    char *id = g_strdup_printf("%s|%04x|%04x|%s", key_salt, vid, pid, serial ? serial : "");
    char *h = g_compute_checksum_for_string(G_CHECKSUM_SHA256, id, -1);
    g_strlcpy(out, h, HASH_LEN);
    g_free(h);
    g_free(id);
}

static int find_key(const char *hash)
{
    for (int i = 0; i < key_count; i++)
        if (strcmp(keys[i].hash, hash) == 0)
            return i;
    return -1;
}

// Format: SALT<TAB>hex | KEY<TAB>hash<TAB>label. Returns -1 if the file exists but is unreadable.
static int load_keys(void)
{
    FILE *f = fopen(key_path, "r");
    if (!f)
        return errno == ENOENT ? 0 : -1;

    char line[512];
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '#' || line[0] == '\0')
            continue;

        char **p = g_strsplit(line, "\t", 3);
        guint n = g_strv_length(p);
        if (n >= 2 && strcmp(p[0], "SALT") == 0) {
            g_strlcpy(key_salt, p[1], sizeof key_salt);
        } else if (n >= 3 && strcmp(p[0], "KEY") == 0 &&
                   strlen(p[1]) == HASH_LEN - 1 && key_count < MAX_KEYS) {
            g_strlcpy(keys[key_count].hash, p[1], HASH_LEN);
            copy_str(keys[key_count].label, sizeof keys[key_count].label, p[2]);
            key_count++;
        }
        g_strfreev(p);
    }
    fclose(f);
    return 0;
}

static int save_keys(void)
{
    FILE *f = fopen(key_path, "w");
    if (!f) {
        g_printerr("Gagal menulis '%s': %s\n", key_path, g_strerror(errno));
        return -1;
    }
    fprintf(f, "# Vault keys (hash only)\n");
    fprintf(f, "SALT\t%s\n", key_salt);
    for (int i = 0; i < key_count; i++)
        fprintf(f, "KEY\t%s\t%s\n", keys[i].hash, keys[i].label);
    fclose(f);
    chmod(key_path, 0600);
    return 0;
}

static void get_physical(libusb_device *dev, char *out, size_t size)
{
    uint8_t ports[8];
    int n = libusb_get_port_numbers(dev, ports, sizeof ports);
    int bus = libusb_get_bus_number(dev);

    if (n <= 0) {
        snprintf(out, size, "bus%d-addr%d", bus, libusb_get_device_address(dev));
        return;
    }
    int len = snprintf(out, size, "%d-%d", bus, ports[0]);
    for (int i = 1; i < n && len > 0 && (size_t)len < size; i++)
        len += snprintf(out + len, size - len, ".%d", ports[i]);
}

// Reads names and serial; returns 1 if any name was read.
static int read_names_libusb(libusb_device *dev, const struct libusb_device_descriptor *desc,
                             char *vendor, char *product, char *serial)
{
    libusb_device_handle *h = NULL;
    int got = 0;

    if (libusb_open(dev, &h) != 0)
        return 0;

    unsigned char buf[STR_LEN];
    if (desc->iManufacturer &&
        libusb_get_string_descriptor_ascii(h, desc->iManufacturer, buf, sizeof buf) > 0) {
        copy_str(vendor, STR_LEN, (char *)buf);
        got = 1;
    }
    if (desc->iProduct &&
        libusb_get_string_descriptor_ascii(h, desc->iProduct, buf, sizeof buf) > 0) {
        copy_str(product, STR_LEN, (char *)buf);
        got = 1;
    }
    if (desc->iSerialNumber &&
        libusb_get_string_descriptor_ascii(h, desc->iSerialNumber, buf, sizeof buf) > 0) {
        copy_str(serial, STR_LEN, (char *)buf);
    }
    libusb_close(h);
    return got;
}

static int read_sysfs_file(const char *physical, const char *name, char *out)
{
    char path[160];
    snprintf(path, sizeof path, "/sys/bus/usb/devices/%s/%s", physical, name);
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    int ok = fgets(out, STR_LEN, f) != NULL;
    fclose(f);
    if (ok) {
        out[strcspn(out, "\r\n")] = '\0';
        sanitize(out);
    }
    return ok && out[0] != '\0';
}

static int read_names_sysfs(const char *physical, char *vendor, char *product)
{
    int a = read_sysfs_file(physical, "manufacturer", vendor);
    int b = read_sysfs_file(physical, "product", product);
    return a || b;
}

enum {
    COL_VENDOR, COL_PRODUCT, COL_VID, COL_PID, COL_PHYS, COL_STATUS, COL_KEY,
    COL_VIDN, COL_PIDN, COL_SAVED, COL_UNKNOWN, COL_SERIAL, N_COLS
};

static GtkListStore *store;
static GtkWidget *main_win, *info_label, *auto_switch, *autolock_switch;
static GtkWidget *stack, *lock_msg;
static libusb_context *usb_ctx;
static GThread *usb_thr;
static volatile gint usb_running = 1;
static char fatal_msg[256] = "";

#define STATUS_SAVED   "\xE2\x97\x8F Tersimpan"
#define STATUS_UNSAVED "\xE2\x97\x8B Belum disimpan"
#define STATUS_KEY     "\xF0\x9F\x94\x91 Key"

static void update_info(void)
{
    int rows = gtk_tree_model_iter_n_children(GTK_TREE_MODEL(store), NULL);
    char *txt;
    if (fatal_msg[0])
        txt = g_strdup(fatal_msg);
    else
        txt = g_strdup_printf("%d device terhubung   |   %d tersimpan di %s   |   %d Physical Key",
                              rows, db_count, db_path, key_count);
    gtk_label_set_text(GTK_LABEL(info_label), txt);
    g_free(txt);
}

static void set_locked(gboolean l)
{
    locked = l;
    gtk_stack_set_visible_child_name(GTK_STACK(stack), l ? "lock" : "db");
    if (l)
        gtk_label_set_text(GTK_LABEL(lock_msg), "Menunggu Physical Key...");
    update_info();
}

static gboolean find_row(uint16_t vid, uint16_t pid, const char *phys, GtkTreeIter *out)
{
    GtkTreeModel *m = GTK_TREE_MODEL(store);
    GtkTreeIter it;
    if (!gtk_tree_model_get_iter_first(m, &it))
        return FALSE;
    do {
        guint v, p;
        gchar *ph;
        gtk_tree_model_get(m, &it, COL_VIDN, &v, COL_PIDN, &p, COL_PHYS, &ph, -1);
        gboolean match = v == vid && p == pid && g_strcmp0(ph, phys) == 0;
        g_free(ph);
        if (match) {
            *out = it;
            return TRUE;
        }
    } while (gtk_tree_model_iter_next(m, &it));
    return FALSE;
}

static void add_row(const char *vendor, const char *product, uint16_t vid, uint16_t pid,
                    const char *phys, const char *serial, gboolean saved, gboolean unknown)
{
    char vs[16], ps[16], hash[HASH_LEN];
    snprintf(vs, sizeof vs, "0x%04x", vid);
    snprintf(ps, sizeof ps, "0x%04x", pid);
    key_hash(vid, pid, serial, hash);
    gboolean iskey = find_key(hash) >= 0;

    GtkTreeIter it;
    gtk_list_store_append(store, &it);
    gtk_list_store_set(store, &it,
        COL_VENDOR, vendor, COL_PRODUCT, product,
        COL_VID, vs, COL_PID, ps, COL_PHYS, phys,
        COL_STATUS, saved ? STATUS_SAVED : STATUS_UNSAVED,
        COL_KEY, iskey ? STATUS_KEY : "",
        COL_VIDN, (guint)vid, COL_PIDN, (guint)pid,
        COL_SAVED, saved, COL_UNKNOWN, unknown,
        COL_SERIAL, serial, -1);
}

// Update all rows with the same VID/PID; NULL vendor/product keeps names.
static void refresh_rows(uint16_t vid, uint16_t pid, const char *vendor, const char *product,
                         gboolean saved)
{
    GtkTreeModel *m = GTK_TREE_MODEL(store);
    GtkTreeIter it;
    if (!gtk_tree_model_get_iter_first(m, &it))
        return;
    do {
        guint v, p;
        gtk_tree_model_get(m, &it, COL_VIDN, &v, COL_PIDN, &p, -1);
        if (v != vid || p != pid)
            continue;
        gtk_list_store_set(store, &it,
            COL_STATUS, saved ? STATUS_SAVED : STATUS_UNSAVED,
            COL_SAVED, saved, -1);
        if (vendor && product) {
            gtk_list_store_set(store, &it,
                COL_VENDOR, vendor, COL_PRODUCT, product, COL_UNKNOWN, FALSE, -1);
        }
    } while (gtk_tree_model_iter_next(m, &it));
}

// Recompute the "Key" column for every connected device.
static void refresh_key_flags(void)
{
    GtkTreeModel *m = GTK_TREE_MODEL(store);
    GtkTreeIter it;
    if (!gtk_tree_model_get_iter_first(m, &it))
        return;
    do {
        guint v, p;
        gchar *serial;
        char hash[HASH_LEN];
        gtk_tree_model_get(m, &it, COL_VIDN, &v, COL_PIDN, &p, COL_SERIAL, &serial, -1);
        key_hash((uint16_t)v, (uint16_t)p, serial, hash);
        gtk_list_store_set(store, &it, COL_KEY, find_key(hash) >= 0 ? STATUS_KEY : "", -1);
        g_free(serial);
    } while (gtk_tree_model_iter_next(m, &it));
}

static int count_key_rows(void)
{
    GtkTreeModel *m = GTK_TREE_MODEL(store);
    GtkTreeIter it;
    int n = 0;
    if (!gtk_tree_model_get_iter_first(m, &it))
        return 0;
    do {
        gchar *k;
        gtk_tree_model_get(m, &it, COL_KEY, &k, -1);
        if (k && k[0])
            n++;
        g_free(k);
    } while (gtk_tree_model_iter_next(m, &it));
    return n;
}

static void show_error(const char *msg)
{
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(main_win), GTK_DIALOG_MODAL,
                                          GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "%s", msg);
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

static gboolean confirm(const char *msg)
{
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(main_win), GTK_DIALOG_MODAL,
                                          GTK_MESSAGE_WARNING, GTK_BUTTONS_YES_NO, "%s", msg);
    gint r = gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
    return r == GTK_RESPONSE_YES;
}

typedef struct {
    int arrived;
    uint16_t vid, pid;
    char vendor[STR_LEN];
    char product[STR_LEN];
    char serial[STR_LEN];
    char physical[PHYS_LEN];
} UsbEvent;

static gboolean handle_event_idle(gpointer data)
{
    UsbEvent *e = data;
    GtkTreeIter it;
    gboolean was_key = FALSE;

    // avoid duplicate rows (also tells us whether the leaving device was a key)
    if (find_row(e->vid, e->pid, e->physical, &it)) {
        gchar *k = NULL;
        gtk_tree_model_get(GTK_TREE_MODEL(store), &it, COL_KEY, &k, -1);
        was_key = k && k[0];
        g_free(k);
        gtk_list_store_remove(store, &it);
    }

    if (e->arrived) {
        // unlock check
        if (locked) {
            char hash[HASH_LEN];
            key_hash(e->vid, e->pid, e->serial, hash);
            if (find_key(hash) >= 0) {
                set_locked(FALSE);
            } else {
                char *m = g_strdup_printf("Device %04x:%04x bukan Physical Key terdaftar.",
                                          e->vid, e->pid);
                gtk_label_set_text(GTK_LABEL(lock_msg), m);
                g_free(m);
            }
        }

        // no database writes while locked
        gboolean can_write = !locked;

        DeviceRecord *rec = find_record(e->vid, e->pid);
        char vendor[STR_LEN], product[STR_LEN];
        copy_str(vendor,  sizeof vendor,  e->vendor);
        copy_str(product, sizeof product, e->product);
        gboolean live = vendor[0] || product[0];
        gboolean saved = FALSE;

        if (live) {
            if (rec) {
                if (can_write) {
                    upsert_record(e->vid, e->pid, vendor, product, e->physical);
                    save_db();
                }
                saved = TRUE;
            } else if (can_write && gtk_switch_get_active(GTK_SWITCH(auto_switch))) {
                if (upsert_record(e->vid, e->pid, vendor, product, e->physical)) {
                    save_db();
                    saved = TRUE;
                }
            }
        } else if (rec) {
            // name unreadable: fall back to the database
            copy_str(vendor,  sizeof vendor,  rec->vendor);
            copy_str(product, sizeof product, rec->product);
            if (can_write)
                copy_str(rec->physical, sizeof rec->physical, e->physical);
            saved = TRUE;
            live = TRUE;
        }

        gboolean unknown = !live;
        if (unknown)
            copy_str(product, sizeof product, UNKNOWN_NAME);

        add_row(vendor, product, e->vid, e->pid, e->physical, e->serial, saved, unknown);
    } else if (was_key && !locked && key_count > 0 &&
               gtk_switch_get_active(GTK_SWITCH(autolock_switch)) &&
               count_key_rows() == 0) {
        // all keys removed: lock
        set_locked(TRUE);
    }

    update_info();
    g_free(e);
    return G_SOURCE_REMOVE;
}

static int LIBUSB_CALL hotplug_cb(libusb_context *ctx, libusb_device *dev,
                                  libusb_hotplug_event ev, void *user_data)
{
    (void)ctx; (void)user_data;

    struct libusb_device_descriptor desc;
    if (libusb_get_device_descriptor(dev, &desc) != 0)
        return 0;

    UsbEvent *e = g_new0(UsbEvent, 1);
    e->arrived = (ev == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED);
    e->vid = desc.idVendor;
    e->pid = desc.idProduct;
    get_physical(dev, e->physical, sizeof e->physical);

    if (e->arrived) {
        if (!read_names_libusb(dev, &desc, e->vendor, e->product, e->serial))
            read_names_sysfs(e->physical, e->vendor, e->product);
        if (!e->serial[0])
            read_sysfs_file(e->physical, "serial", e->serial);
    }

    g_idle_add(handle_event_idle, e);
    return 0;
}

static gboolean error_idle(gpointer data)
{
    char *msg = data;
    copy_str(fatal_msg, sizeof fatal_msg, msg);
    update_info();
    g_free(msg);
    return G_SOURCE_REMOVE;
}

static gpointer usb_thread(gpointer data)
{
    (void)data;
    libusb_hotplug_callback_handle h;
    int rc = libusb_hotplug_register_callback(
        usb_ctx,
        LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED | LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT,
        SCAN_EXISTING ? LIBUSB_HOTPLUG_ENUMERATE : LIBUSB_HOTPLUG_NO_FLAGS,
        LIBUSB_HOTPLUG_MATCH_ANY, LIBUSB_HOTPLUG_MATCH_ANY, LIBUSB_HOTPLUG_MATCH_ANY,
        hotplug_cb, NULL, &h);
    if (rc != LIBUSB_SUCCESS) {
        g_idle_add(error_idle, g_strdup_printf("Hotplug gagal: %s", libusb_error_name(rc)));
        return NULL;
    }

    struct timeval tv = {0, 200000};
    while (g_atomic_int_get(&usb_running))
        libusb_handle_events_timeout_completed(usb_ctx, &tv, NULL);

    libusb_hotplug_deregister_callback(usb_ctx, h);
    return NULL;
}

typedef struct {
    uint16_t vid, pid;
    char phys[PHYS_LEN];
    char vendor[STR_LEN];
    char product[STR_LEN];
    char serial[STR_LEN];
    gboolean saved, unknown, iskey;
} RowKey;

static gboolean ask_names(char *vendor, char *product)
{
    GtkWidget *d = gtk_dialog_new_with_buttons("Beri nama device", GTK_WINDOW(main_win),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "Batal", GTK_RESPONSE_CANCEL, "Simpan", GTK_RESPONSE_OK, NULL);
    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(d));
    gtk_container_set_border_width(GTK_CONTAINER(box), 14);
    gtk_box_set_spacing(GTK_BOX(box), 10);

    GtkWidget *lbl = gtk_label_new("Device ini tidak punya nama.\nIsi nama agar dikenali di lain waktu:");
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
    GtkWidget *ve = gtk_entry_new();
    GtkWidget *pe = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(ve), "Vendor");
    gtk_entry_set_placeholder_text(GTK_ENTRY(pe), "Nama produk");
    gtk_box_pack_start(GTK_BOX(box), lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), ve,  FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), pe,  FALSE, FALSE, 0);
    gtk_widget_show_all(d);

    gboolean ok = FALSE;
    while (gtk_dialog_run(GTK_DIALOG(d)) == GTK_RESPONSE_OK) {
        const char *v = gtk_entry_get_text(GTK_ENTRY(ve));
        const char *p = gtk_entry_get_text(GTK_ENTRY(pe));
        if (v[0] || p[0]) {
            copy_str(vendor,  STR_LEN, v);
            copy_str(product, STR_LEN, p);
            ok = TRUE;
            break;
        }
    }
    gtk_widget_destroy(d);
    return ok;
}

static void on_menu_save(GtkMenuItem *item, gpointer data)
{
    (void)item;
    RowKey *k = data;
    char vendor[STR_LEN], product[STR_LEN];
    copy_str(vendor,  sizeof vendor,  k->vendor);
    copy_str(product, sizeof product, k->product);

    if (k->unknown && !ask_names(vendor, product))
        return;

    if (!upsert_record(k->vid, k->pid, vendor, product, k->phys)) {
        show_error("Database penuh, device tidak bisa disimpan.");
        return;
    }
    save_db();
    refresh_rows(k->vid, k->pid, vendor, product, TRUE);
    update_info();
}

static void on_menu_forget(GtkMenuItem *item, gpointer data)
{
    (void)item;
    RowKey *k = data;
    remove_record(k->vid, k->pid);
    save_db();
    refresh_rows(k->vid, k->pid, NULL, NULL, FALSE);
    update_info();
}

static void on_menu_setkey(GtkMenuItem *item, gpointer data)
{
    (void)item;
    RowKey *k = data;

    if (key_count >= MAX_KEYS) {
        show_error("Jumlah Physical Key sudah maksimum.");
        return;
    }
    if (!k->serial[0] &&
        !confirm("Device ini tidak punya serial number.\n"
                 "Semua device dengan VID/PID yang sama akan bisa membuka vault.\n\n"
                 "Tetap jadikan Physical Key?"))
        return;

    if (!key_salt[0])
        gen_salt();

    char hash[HASH_LEN];
    key_hash(k->vid, k->pid, k->serial, hash);
    if (find_key(hash) >= 0) {
        show_error("Device ini sudah menjadi Physical Key.");
        return;
    }

    KeyRecord *kr = &keys[key_count];
    g_strlcpy(kr->hash, hash, HASH_LEN);
    if (k->unknown || (!k->vendor[0] && !k->product[0]))
        snprintf(kr->label, sizeof kr->label, "Device %04x:%04x", k->vid, k->pid);
    else
        snprintf(kr->label, sizeof kr->label, "%s %s", k->vendor, k->product);
    sanitize(kr->label);
    key_count++;

    if (save_keys() != 0) {
        key_count--;
        show_error("Gagal menyimpan daftar Physical Key.");
        return;
    }
    refresh_key_flags();
    update_info();
}

static void on_menu_unsetkey(GtkMenuItem *item, gpointer data)
{
    (void)item;
    RowKey *k = data;
    char hash[HASH_LEN];
    key_hash(k->vid, k->pid, k->serial, hash);
    int idx = find_key(hash);
    if (idx < 0)
        return;

    if (key_count == 1 &&
        !confirm("Ini Physical Key terakhir.\nSetelah dicabut, vault tidak akan terkunci lagi.\n\nLanjutkan?"))
        return;

    KeyRecord backup = keys[idx];
    memmove(&keys[idx], &keys[idx + 1], (key_count - idx - 1) * sizeof keys[0]);
    key_count--;

    if (save_keys() != 0) {
        // rollback
        memmove(&keys[idx + 1], &keys[idx], (key_count - idx) * sizeof keys[0]);
        keys[idx] = backup;
        key_count++;
        show_error("Gagal menyimpan daftar Physical Key.");
        return;
    }
    refresh_key_flags();
    update_info();
}

static gboolean destroy_menu_idle(gpointer menu)
{
    gtk_widget_destroy(GTK_WIDGET(menu));
    return G_SOURCE_REMOVE;
}

static void on_menu_done(GtkMenuShell *menu, gpointer data)
{
    (void)data;
    g_idle_add(destroy_menu_idle, menu);
}

static gboolean on_tree_click(GtkWidget *tv, GdkEventButton *ev, gpointer data)
{
    (void)data;
    if (ev->type != GDK_BUTTON_PRESS || (ev->button != 1 && ev->button != 3))
        return FALSE;

    GtkTreePath *path = NULL;
    if (!gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(tv), (gint)ev->x, (gint)ev->y,
                                       &path, NULL, NULL, NULL))
        return FALSE;

    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(tv));
    gtk_tree_selection_select_path(sel, path);

    GtkTreeIter it;
    if (!gtk_tree_model_get_iter(GTK_TREE_MODEL(store), &it, path)) {
        gtk_tree_path_free(path);
        return FALSE;
    }
    gtk_tree_path_free(path);

    RowKey *k = g_new0(RowKey, 1);
    guint v, p;
    gchar *vendor, *product, *phys, *serial, *keytxt;
    gtk_tree_model_get(GTK_TREE_MODEL(store), &it,
        COL_VIDN, &v, COL_PIDN, &p, COL_VENDOR, &vendor, COL_PRODUCT, &product,
        COL_PHYS, &phys, COL_SERIAL, &serial, COL_KEY, &keytxt,
        COL_SAVED, &k->saved, COL_UNKNOWN, &k->unknown, -1);
    k->vid = (uint16_t)v;
    k->pid = (uint16_t)p;
    k->iskey = keytxt && keytxt[0];
    copy_str(k->vendor,  sizeof k->vendor,  vendor);
    copy_str(k->product, sizeof k->product, product);
    copy_str(k->phys,    sizeof k->phys,    phys);
    copy_str(k->serial,  sizeof k->serial,  serial ? serial : "");
    g_free(vendor); g_free(product); g_free(phys); g_free(serial); g_free(keytxt);

    GtkWidget *menu = gtk_menu_new();
    g_object_set_data_full(G_OBJECT(menu), "rowkey", k, g_free);

    GtkWidget *save_item   = gtk_menu_item_new_with_label("Simpan");
    GtkWidget *forget_item = gtk_menu_item_new_with_label("Hapus dari database");
    GtkWidget *setkey_item = gtk_menu_item_new_with_label("Jadikan Physical Key");
    GtkWidget *unkey_item  = gtk_menu_item_new_with_label("Cabut status Physical Key");
    gtk_widget_set_sensitive(save_item,   !k->saved);
    gtk_widget_set_sensitive(forget_item,  k->saved);
    gtk_widget_set_sensitive(setkey_item, !k->iskey);
    gtk_widget_set_sensitive(unkey_item,   k->iskey);
    g_signal_connect(save_item,   "activate", G_CALLBACK(on_menu_save),     k);
    g_signal_connect(forget_item, "activate", G_CALLBACK(on_menu_forget),   k);
    g_signal_connect(setkey_item, "activate", G_CALLBACK(on_menu_setkey),   k);
    g_signal_connect(unkey_item,  "activate", G_CALLBACK(on_menu_unsetkey), k);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), save_item);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), forget_item);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), gtk_separator_menu_item_new());
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), setkey_item);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), unkey_item);
    g_signal_connect(menu, "selection-done", G_CALLBACK(on_menu_done), NULL);
    gtk_widget_show_all(menu);
    gtk_menu_popup_at_pointer(GTK_MENU(menu), (GdkEvent *)ev);
    return FALSE;
}

static void on_lock_clicked(GtkButton *b, gpointer data)
{
    (void)b; (void)data;
    if (key_count == 0) {
        show_error("Belum ada Physical Key terdaftar.\n"
                   "Klik sebuah device, lalu pilih \"Jadikan Physical Key\".");
        return;
    }
    set_locked(TRUE);
}

static void apply_css(void)
{
    const char *css =
        "* { font-family: \"JetBrains Mono\", monospace; font-size: 12px; }"
        "window { background-color: #000000; color: #FFFFFF; }"
        "label { color: #FFFFFF; }"
        "#title { color: #87CEEB; font-size: 22px; font-weight: bold; }"
        "#lockicon { font-size: 72px; }"
        "#info { color: #87CEEB; }"
        "#hint { color: #8A8A8A; }"
        "scrolledwindow { border: 1px solid #87CEEB; }"
        "treeview.view { background-color: #0A0A0A; color: #FFFFFF; }"
        "treeview.view:hover { background-color: #12303D; }"
        "treeview.view:selected { background-color: #87CEEB; color: #000000; }"
        "treeview header button { background-image: none; background-color: #000000;"
        "  color: #87CEEB; font-weight: bold; border: none; border-radius: 0;"
        "  border-bottom: 2px solid #87CEEB; box-shadow: none; padding: 8px; }"
        "treeview header button label { color: #87CEEB; }"
        "switch { background-color: #333333; border: 1px solid #87CEEB; color: #FFFFFF; }"
        "switch:checked { background-color: #87CEEB; }"
        "switch slider { background-color: #FFFFFF; border-color: #000000; }"
        "menu { background-color: #000000; border: 1px solid #87CEEB; color: #FFFFFF; }"
        "menuitem { color: #FFFFFF; padding: 6px 14px; }"
        "menuitem label { color: #FFFFFF; }"
        "menuitem:hover { background-color: #87CEEB; }"
        "menuitem:hover label { color: #000000; }"
        "menuitem:disabled label { color: #555555; }"
        "button { background-image: none; background-color: #87CEEB; color: #000000;"
        "  border: none; border-radius: 4px; padding: 6px 16px; font-weight: bold; box-shadow: none; }"
        "button label { color: #000000; }"
        "entry { background-color: #0A0A0A; color: #FFFFFF; border: 1px solid #87CEEB;"
        "  caret-color: #87CEEB; padding: 6px; }";

    GtkCssProvider *prov = gtk_css_provider_new();
    gtk_css_provider_load_from_data(prov, css, -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(prov), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(prov);
}

static void add_text_column(GtkWidget *tv, const char *title, int col, gboolean expand)
{
    GtkCellRenderer *r = gtk_cell_renderer_text_new();
    g_object_set(r, "xpad", 8, "ypad", 7, NULL);
    if (expand)
        g_object_set(r, "ellipsize", PANGO_ELLIPSIZE_END, NULL);
    GtkTreeViewColumn *c = gtk_tree_view_column_new_with_attributes(title, r, "text", col, NULL);
    gtk_tree_view_column_set_resizable(c, TRUE);
    gtk_tree_view_column_set_expand(c, expand);
    gtk_tree_view_append_column(GTK_TREE_VIEW(tv), c);
}

static GtkWidget *build_lock_page(void)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);
    gtk_widget_set_halign(box, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(box, GTK_ALIGN_CENTER);

    GtkWidget *icon = gtk_label_new("\xF0\x9F\x94\x92");
    gtk_widget_set_name(icon, "lockicon");

    GtkWidget *title = gtk_label_new("VAULT TERKUNCI");
    gtk_widget_set_name(title, "title");

    GtkWidget *sub = gtk_label_new("Colokkan Physical Key untuk membuka");
    gtk_widget_set_name(sub, "info");

    lock_msg = gtk_label_new("Menunggu Physical Key...");
    gtk_widget_set_name(lock_msg, "hint");

    gtk_box_pack_start(GTK_BOX(box), icon,     FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), title,    FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), sub,      FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), lock_msg, FALSE, FALSE, 0);
    return box;
}

static GtkWidget *build_db_page(void)
{
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);

    GtkWidget *top = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *title = gtk_label_new("CONNECTED DETECTOR");
    gtk_widget_set_name(title, "title");
    gtk_box_pack_start(GTK_BOX(top), title, FALSE, FALSE, 0);

    GtkWidget *lock_btn = gtk_button_new_with_label("Kunci");
    g_signal_connect(lock_btn, "clicked", G_CALLBACK(on_lock_clicked), NULL);
    gtk_box_pack_end(GTK_BOX(top), lock_btn, FALSE, FALSE, 0);

    autolock_switch = gtk_switch_new();
    gtk_switch_set_active(GTK_SWITCH(autolock_switch), TRUE);
    gtk_widget_set_valign(autolock_switch, GTK_ALIGN_CENTER);
    GtkWidget *autolock_lbl = gtk_label_new("Kunci saat key dicabut");
    gtk_box_pack_end(GTK_BOX(top), autolock_switch, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(top), autolock_lbl, FALSE, FALSE, 0);

    auto_switch = gtk_switch_new();
    gtk_switch_set_active(GTK_SWITCH(auto_switch), TRUE);
    gtk_widget_set_valign(auto_switch, GTK_ALIGN_CENTER);
    GtkWidget *auto_lbl = gtk_label_new("Simpan otomatis");
    gtk_box_pack_end(GTK_BOX(top), auto_switch, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(top), auto_lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(page), top, FALSE, FALSE, 0);

    info_label = gtk_label_new("");
    gtk_widget_set_name(info_label, "info");
    gtk_label_set_xalign(GTK_LABEL(info_label), 0.0);
    gtk_box_pack_start(GTK_BOX(page), info_label, FALSE, FALSE, 0);

    store = gtk_list_store_new(N_COLS,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
        G_TYPE_STRING, G_TYPE_STRING,
        G_TYPE_UINT, G_TYPE_UINT, G_TYPE_BOOLEAN, G_TYPE_BOOLEAN,
        G_TYPE_STRING);

    GtkWidget *tv = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(tv), TRUE);
    add_text_column(tv, "Vendor",   COL_VENDOR,  TRUE);
    add_text_column(tv, "Produk",   COL_PRODUCT, TRUE);
    add_text_column(tv, "VID",      COL_VID,     FALSE);
    add_text_column(tv, "PID",      COL_PID,     FALSE);
    add_text_column(tv, "Physical", COL_PHYS,    FALSE);
    add_text_column(tv, "Status",   COL_STATUS,  FALSE);
    add_text_column(tv, "Key",      COL_KEY,     FALSE);
    g_signal_connect(tv, "button-press-event", G_CALLBACK(on_tree_click), NULL);

    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scroll), tv);
    gtk_widget_set_hexpand(scroll, TRUE);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_box_pack_start(GTK_BOX(page), scroll, TRUE, TRUE, 0);

    GtkWidget *hint = gtk_label_new("Klik sebuah baris untuk opsi Simpan / Physical Key");
    gtk_widget_set_name(hint, "hint");
    gtk_box_pack_start(GTK_BOX(page), hint, FALSE, FALSE, 0);

    return page;
}

static void build_ui(void)
{
    main_win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(main_win), "Connected Detector - Vault");
    gtk_window_set_default_size(GTK_WINDOW(main_win), 960, 560);
    g_signal_connect(main_win, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(stack), GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    gtk_container_set_border_width(GTK_CONTAINER(stack), 20);
    gtk_container_add(GTK_CONTAINER(main_win), stack);

    gtk_stack_add_named(GTK_STACK(stack), build_db_page(),   "db");
    gtk_stack_add_named(GTK_STACK(stack), build_lock_page(), "lock");
}

int main(int argc, char **argv)
{
    gtk_init(&argc, &argv);
    if (argc > 1)
        db_path = argv[1];
    key_path = g_strdup_printf("%s.keys", db_path);

    apply_css();
    build_ui();
    load_db();

    // fail closed if the key file is unreadable
    if (load_keys() != 0) {
        char *m = g_strdup_printf("Tidak bisa membaca '%s': %s", key_path, g_strerror(errno));
        show_error(m);
        g_free(m);
        return 1;
    }

    gtk_widget_show_all(main_win);
    set_locked(key_count > 0);  // no keys -> straight to database

    if (libusb_init(&usb_ctx) != 0) {
        show_error("libusb_init gagal.");
        return 1;
    }
    if (!libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG)) {
        show_error("Platform ini tidak mendukung hotplug di libusb (mis. Windows). Gunakan Linux/macOS.");
        libusb_exit(usb_ctx);
        return 1;
    }

    usb_thr = g_thread_new("usb-events", usb_thread, NULL);
    gtk_main();

    g_atomic_int_set(&usb_running, 0);
    g_thread_join(usb_thr);
    libusb_exit(usb_ctx);
    g_free(key_path);
    return 0;
}