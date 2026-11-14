/*
 * Connected Detector
 *
 * - Mendeteksi USB yang dicolok / dicabut selama program berjalan.
 * - Setiap device dicatat: nama vendor, nama produk, VID, PID, dan
 *   physical name (jalur bus-port, contoh "1-2.3").
 * - Saat program dihentikan (Ctrl+C), semua catatan disimpan ke file.
 * - Saat program dijalankan lagi, file dibaca. Device yang sama (VID+PID)
 *   langsung dikenali, tidak lagi tampil sebagai "Unknown device".
 *
 * Build : gcc main.c -o connected_detector $(pkg-config --cflags --libs libusb-1.0)
 * Run   : ./connected_detector [file_database]
 *         (default file: known_devices.txt)
 */

#include <libusb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define MAX_DEVICES      100
#define STR_LEN          128
#define PHYS_LEN         64
#define DB_FILE_DEFAULT  "known_devices.txt"

typedef struct {
    uint16_t vid;
    uint16_t pid;
    char vendor[STR_LEN];
    char product[STR_LEN];
    char physical[PHYS_LEN];   /* port terakhir tempat device terlihat */
    int  seen_now;             /* 1 jika muncul pada sesi ini */
} DeviceRecord;

static DeviceRecord db[MAX_DEVICES];
static int db_count = 0;
static const char *db_path = DB_FILE_DEFAULT;
static volatile sig_atomic_t running = 1;

/* ---------- util ---------- */

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

/* ---------- database file ---------- */

/* Format per baris: VID<TAB>PID<TAB>vendor<TAB>product<TAB>physical */
static void load_db(void)
{
    FILE *f = fopen(db_path, "r");
    if (!f) {
        printf("[info] File database '%s' belum ada, akan dibuat otomatis.\n", db_path);
        return;
    }

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

        DeviceRecord *r = &db[db_count];
        memset(r, 0, sizeof *r);
        r->vid = (uint16_t)strtoul(fields[0], NULL, 16);
        r->pid = (uint16_t)strtoul(fields[1], NULL, 16);
        copy_str(r->vendor,   sizeof r->vendor,   fields[2]);
        copy_str(r->product,  sizeof r->product,  fields[3]);
        copy_str(r->physical, sizeof r->physical, fields[4]);
        db_count++;
    }
    fclose(f);
    printf("[info] %d device dimuat dari '%s'.\n", db_count, db_path);
}

static int save_db(void)
{
    FILE *f = fopen(db_path, "w");
    if (!f) {
        perror("[error] Gagal menulis file database");
        return -1;
    }
    fprintf(f, "# VID\tPID\tVendor\tProduct\tPhysical\n");
    for (int i = 0; i < db_count; i++)
        fprintf(f, "%04x\t%04x\t%s\t%s\t%s\n",
                db[i].vid, db[i].pid,
                db[i].vendor, db[i].product, db[i].physical);
    fclose(f);
    return 0;
}

/* ---------- membaca info device ---------- */

/* Physical name = jalur bus-port, mis. "1-2.3" (sama dengan nama di /sys/bus/usb/devices) */
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

/* Cara 1: baca string descriptor lewat libusb (butuh izin akses device) */
static int read_names_libusb(libusb_device *dev, const struct libusb_device_descriptor *desc,
                             char *vendor, char *product)
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
    libusb_close(h);
    return got;
}

/* Cara 2 (Linux): baca dari sysfs, tidak butuh root */
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

/* ---------- tampilan ---------- */

static void print_device_line(const char *tag, const char *vendor, const char *product,
                              uint16_t vid, uint16_t pid, const char *physical, const char *note)
{
    if (vendor[0] == '\0' && product[0] == '\0') {
        printf("%s Unknown device | VID=0x%04x PID=0x%04x | Physical=%s\n",
               tag, vid, pid, physical);
    } else {
        printf("%s %s %s | VID=0x%04x PID=0x%04x | Physical=%s%s\n",
               tag,
               vendor[0]  ? vendor  : "(vendor ?)",
               product[0] ? product : "(product ?)",
               vid, pid, physical, note);
    }
}

/* ---------- hotplug ---------- */

static int LIBUSB_CALL hotplug_callback(libusb_context *ctx, libusb_device *dev,
                                        libusb_hotplug_event event, void *user_data)
{
    (void)ctx; (void)user_data;

    struct libusb_device_descriptor desc;
    if (libusb_get_device_descriptor(dev, &desc) != 0)
        return 0;

    char physical[PHYS_LEN];
    get_physical(dev, physical, sizeof physical);

    DeviceRecord *rec = find_record(desc.idVendor, desc.idProduct);

    if (event == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED) {
        char vendor[STR_LEN]  = "";
        char product[STR_LEN] = "";

        /* Coba baca nama langsung dari device */
        int live = read_names_libusb(dev, &desc, vendor, product);
        if (!live)
            live = read_names_sysfs(physical, vendor, product);

        if (live) {
            if (!rec) {
                if (db_count >= MAX_DEVICES) {
                    printf("[warn] Database penuh (%d), device tidak disimpan.\n", MAX_DEVICES);
                } else {
                    rec = &db[db_count++];
                    memset(rec, 0, sizeof *rec);
                    rec->vid = desc.idVendor;
                    rec->pid = desc.idProduct;
                }
                if (rec) {
                    copy_str(rec->vendor,  sizeof rec->vendor,  vendor);
                    copy_str(rec->product, sizeof rec->product, product);
                    copy_str(rec->physical, sizeof rec->physical, physical);
                    rec->seen_now = 1;
                    print_device_line("[PLUGGED] ", vendor, product, desc.idVendor,
                                      desc.idProduct, physical, "  (device baru, disimpan)");
                    save_db(); /* simpan segera agar tidak hilang jika program mati mendadak */
                } else {
                    print_device_line("[PLUGGED] ", vendor, product, desc.idVendor,
                                      desc.idProduct, physical, "");
                }
            } else {
                /* Sudah dikenal: perbarui nama bila ada yang lebih lengkap */
                if (vendor[0])  copy_str(rec->vendor,  sizeof rec->vendor,  vendor);
                if (product[0]) copy_str(rec->product, sizeof rec->product, product);
                copy_str(rec->physical, sizeof rec->physical, physical);
                rec->seen_now = 1;
                print_device_line("[PLUGGED] ", rec->vendor, rec->product, desc.idVendor,
                                  desc.idProduct, physical, "  (dikenal)");
            }
        } else if (rec) {
            /* Nama tidak bisa dibaca, tapi ada di database -> pakai catatan lama */
            copy_str(rec->physical, sizeof rec->physical, physical);
            rec->seen_now = 1;
            print_device_line("[PLUGGED] ", rec->vendor, rec->product, desc.idVendor,
                              desc.idProduct, physical, "  (dari database)");
        } else {
            print_device_line("[PLUGGED] ", "", "", desc.idVendor, desc.idProduct, physical, "");
        }
    } else if (event == LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT) {
        if (rec)
            print_device_line("[REMOVED] ", rec->vendor, rec->product, desc.idVendor,
                              desc.idProduct, physical, "");
        else
            print_device_line("[REMOVED] ", "", "", desc.idVendor, desc.idProduct, physical, "");
    }
    return 0;
}

static void on_signal(int sig)
{
    (void)sig;
    running = 0;
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
    if (argc > 1)
        db_path = argv[1];

    libusb_context *ctx = NULL;
    if (libusb_init(&ctx) != 0) {
        fprintf(stderr, "[error] libusb_init gagal\n");
        return 1;
    }

    if (!libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG)) {
        fprintf(stderr, "[error] Platform ini tidak mendukung hotplug di libusb.\n");
        libusb_exit(ctx);
        return 1;
    }

    load_db();

    signal(SIGINT, on_signal);
#ifdef SIGTERM
    signal(SIGTERM, on_signal);
#endif

    libusb_hotplug_callback_handle handle;
    int rc = libusb_hotplug_register_callback(
        ctx,
        LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED | LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT,
        LIBUSB_HOTPLUG_NO_FLAGS,
        LIBUSB_HOTPLUG_MATCH_ANY, LIBUSB_HOTPLUG_MATCH_ANY, LIBUSB_HOTPLUG_MATCH_ANY,
        hotplug_callback, NULL, &handle);
    if (rc != LIBUSB_SUCCESS) {
        fprintf(stderr, "[error] Gagal mendaftarkan hotplug callback: %s\n", libusb_error_name(rc));
        libusb_exit(ctx);
        return 1;
    }

    printf("Menunggu perangkat USB... (tekan Ctrl+C untuk berhenti)\n");

    struct timeval tv = {1, 0};
    while (running)
        libusb_handle_events_timeout_completed(ctx, &tv, NULL);

    libusb_hotplug_deregister_callback(ctx, handle);

    /* Ringkasan sesi */
    printf("\n=== Device yang terdeteksi pada sesi ini ===\n");
    int shown = 0;
    for (int i = 0; i < db_count; i++) {
        if (!db[i].seen_now)
            continue;
        printf("  %s %s | VID=0x%04x PID=0x%04x | Physical=%s\n",
               db[i].vendor, db[i].product, db[i].vid, db[i].pid, db[i].physical);
        shown++;
    }
    if (!shown)
        printf("  (tidak ada)\n");

    if (save_db() == 0)
        printf("Tersimpan: %d device total di '%s'\n", db_count, db_path);

    libusb_exit(ctx);
    return 0;
}