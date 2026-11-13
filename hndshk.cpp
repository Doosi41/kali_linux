// hndshk.cpp
//
// Учебный сниффер WPA/WPA2 4-way handshake (EAPOL) для задания по ОС.
// ТОЛЬКО перехват и сохранение в .pcap — никакого подбора/взлома пароля.
//
// Требования:
//   - Linux, сетевой адаптер в monitor mode (настраивается заранее,
//     например: airmon-ng start wlan0 / iw dev wlan0 set monitor control)
//   - libpcap-dev (apt install libpcap-dev)
//
// Сборка:
//   g++ -O2 -Wall -std=c++11 -o hndshk hndshk.cpp -lpcap
//
// Запуск (нужны права root для сырого захвата):
//   sudo ./hndshk wlan0mon handshake.pcap
//   sudo ./hndshk wlan0mon handshake.pcap -b AA:BB:CC:DD:EE:FF
//   sudo ./hndshk wlan0mon handshake.pcap --once
//
// Как это работает (для отчёта/понимания):
//   802.11 кадр в эфире -> (radiotap header) -> (802.11 MAC header) ->
//   LLC/SNAP -> EtherType 0x888E (EAPOL) -> EAPOL-Key фрейм.
//   В 4-way handshake 4 EAPOL-Key сообщения различаются битами поля
//   Key Information:
//     msg1: ACK=1, MIC=0                (AP  -> STA, несёт ANonce)
//     msg2: ACK=0, MIC=1, Secure=0      (STA -> AP,  несёт SNonce + MIC)
//     msg3: ACK=1, MIC=1, Secure=1      (AP  -> STA)
//     msg4: ACK=0, MIC=1, Secure=1      (STA -> AP)
//   Программа ничего не расшифровывает — просто узнаёт тип сообщения по
//   этим битам и сохраняет исходный кадр целиком в выходной .pcap, который
//   потом можно открыть в Wireshark или подать в aircrack-ng/hashcat.

#include <pcap.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <map>
#include <ctime>

// ---------- вспомогательные структуры ----------

#pragma pack(push, 1)
struct RadiotapHeader {
    uint8_t  it_version;
    uint8_t  it_pad;
    uint16_t it_len;      // полная длина radiotap-заголовка (little-endian)
    uint32_t it_present;  // битовая маска присутствующих полей (не разбираем)
};
#pragma pack(pop)

static std::string mac_to_str(const uint8_t *m) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             m[0], m[1], m[2], m[3], m[4], m[5]);
    return std::string(buf);
}

// ---------- глобальное состояние захвата ----------

struct Options {
    std::string iface;
    std::string outfile = "handshake.pcap";
    bool have_bssid_filter = false;
    uint8_t bssid_filter[6] = {0};
    bool once = false;      // остановиться после первого полного handshake
} g_opt;

pcap_dumper_t *g_dumper = nullptr;

// клиент(MAC) -> битовая маска увиденных сообщений (бит i = msg (i+1) увиден)
std::map<std::string, uint8_t> g_seen;
bool g_got_full_handshake = false;

static bool parse_mac(const char *s, uint8_t out[6]) {
    unsigned v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
        return false;
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)v[i];
    return true;
}

// ---------- разбор одного кадра ----------

static void handle_packet(u_char *user, const struct pcap_pkthdr *hdr, const u_char *bytes) {
    (void)user;

    if (hdr->caplen < sizeof(RadiotapHeader)) return;

    const RadiotapHeader *rt = reinterpret_cast<const RadiotapHeader *>(bytes);
    uint16_t rt_len = rt->it_len; // уже little-endian на x86/arm little-endian хостах
    if (rt_len == 0 || rt_len > hdr->caplen) return;

    const uint8_t *dot11 = bytes + rt_len;
    size_t remaining = hdr->caplen - rt_len;
    if (remaining < 24) return; // минимальный 802.11 заголовок

    uint8_t fc0 = dot11[0]; // subtype(4) type(2) version(2), упакованные как байт
    uint8_t fc1 = dot11[1]; // flags: ToDS, FromDS, ...
    uint8_t type    = (fc0 >> 2) & 0x3;
    uint8_t subtype = (fc0 >> 4) & 0xF;
    bool to_ds   = fc1 & 0x01;
    bool from_ds = fc1 & 0x02;

    if (type != 2) return; // интересуют только Data-кадры

    size_t hdr_len = 24;
    if (to_ds && from_ds) hdr_len += 6; // Address 4 (WDS)
    bool is_qos = (subtype & 0x08) != 0;
    if (is_qos) hdr_len += 2; // QoS Control

    if (remaining < hdr_len + 8 /*LLC/SNAP*/ + 4 /*EAPOL header*/) return;

    const uint8_t *addr1 = dot11 + 4;  // receiver / DA
    const uint8_t *addr2 = dot11 + 10; // transmitter / SA
    const uint8_t *addr3 = dot11 + 16; // BSSID (в типичном случае)

    // Определяем, кто тут AP (BSSID) и кто клиент (STA), по ToDS/FromDS.
    const uint8_t *bssid;
    const uint8_t *station;
    if (to_ds && !from_ds) {       // STA -> AP
        bssid = addr1; station = addr2;
    } else if (!to_ds && from_ds) { // AP -> STA
        bssid = addr2; station = addr1;
    } else {
        bssid = addr3; station = addr2; // ad-hoc/WDS — грубое приближение
    }

    if (g_opt.have_bssid_filter &&
        memcmp(bssid, g_opt.bssid_filter, 6) != 0) {
        return; // не наша точка доступа
    }

    const uint8_t *llc = dot11 + hdr_len;
    // LLC/SNAP: AA AA 03 00 00 00 <ethertype:2>
    if (!(llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03)) return;
    uint16_t ethertype = (llc[6] << 8) | llc[7];
    if (ethertype != 0x888E) return; // не EAPOL

    const uint8_t *eapol = llc + 8;
    size_t eapol_avail = remaining - hdr_len - 8;
    if (eapol_avail < 4 + 1 + 2) return; // version+type+len, descriptor_type, key_info

    // eapol[0]=version, eapol[1]=type(должен быть 3 = Key), eapol[2..3]=length (не нужна)
    if (eapol[1] != 3) return; // не EAPOL-Key фрейм

    uint8_t descriptor_type = eapol[4];
    (void)descriptor_type;
    uint16_t key_info = (eapol[5] << 8) | eapol[6];

    bool key_ack  = (key_info >> 7) & 1;
    bool key_mic  = (key_info >> 8) & 1;
    bool secure   = (key_info >> 9) & 1;

    int msg = 0;
    if (!key_mic && key_ack)                 msg = 1;
    else if (key_mic && !key_ack && !secure) msg = 2;
    else if (key_mic && key_ack && secure)   msg = 3;
    else if (key_mic && !key_ack && secure)  msg = 4;
    else return; // что-то не из стандартных 4 сообщений (например, Group Key Handshake)

    std::string sta_str = mac_to_str(station);
    std::string bssid_str = mac_to_str(bssid);

    uint8_t &mask = g_seen[sta_str];
    bool new_msg = !(mask & (1 << (msg - 1)));
    mask |= (1 << (msg - 1));

    if (new_msg) {
        time_t now = time(nullptr);
        char tbuf[9];
        strftime(tbuf, sizeof(tbuf), "%H:%M:%S", localtime(&now));
        printf("[%s] AP %s  STA %s  -> EAPOL msg %d/4\n",
               tbuf, bssid_str.c_str(), sta_str.c_str(), msg);
    }

    // Сохраняем кадр как есть — целиком, с radiotap-заголовком —
    // чтобы файл был валиден для Wireshark/aircrack-ng.
    pcap_dump(reinterpret_cast<u_char *>(g_dumper), hdr, bytes);
    pcap_dump_flush(g_dumper);

    if (mask == 0x0F && !g_got_full_handshake) {
        g_got_full_handshake = true;
        printf(">>> Полный 4-way handshake для STA %s (AP %s) сохранён в %s\n",
               sta_str.c_str(), bssid_str.c_str(), g_opt.outfile.c_str());
        if (g_opt.once) {
            pcap_breakloop(reinterpret_cast<pcap_t *>(user));
        }
    }
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <iface-in-monitor-mode> [output.pcap] [-b BSSID] [--once]\n"
        "  -b AA:BB:CC:DD:EE:FF   захватывать только handshake для этой точки доступа\n"
        "  --once                 завершиться после первого полного handshake\n",
        prog);
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 1; }

    g_opt.iface = argv[1];
    int i = 2;
    if (i < argc && argv[i][0] != '-') {
        g_opt.outfile = argv[i];
        i++;
    }
    for (; i < argc; i++) {
        std::string a = argv[i];
        if (a == "-b" && i + 1 < argc) {
            if (!parse_mac(argv[++i], g_opt.bssid_filter)) {
                fprintf(stderr, "Неверный формат MAC в -b\n");
                return 1;
            }
            g_opt.have_bssid_filter = true;
        } else if (a == "--once") {
            g_opt.once = true;
        } else {
            fprintf(stderr, "Неизвестный аргумент: %s\n", a.c_str());
            usage(argv[0]);
            return 1;
        }
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(g_opt.iface.c_str(), 65535 /*snaplen*/,
                                     1 /*promisc*/, 100 /*ms timeout*/, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", g_opt.iface.c_str(), errbuf);
        fprintf(stderr, "Убедитесь, что интерфейс переведён в monitor mode "
                        "(например: sudo airmon-ng start wlan0) и запущено с sudo.\n");
        return 1;
    }

    int dlt = pcap_datalink(handle);
    if (dlt != DLT_IEEE802_11_RADIO) {
        fprintf(stderr,
            "Предупреждение: datalink = %d (%s), ожидался DLT_IEEE802_11_RADIO.\n"
            "Если интерфейс не в monitor mode, EAPOL-кадры других устройств не видны.\n",
            dlt, pcap_datalink_val_to_name(dlt) ? pcap_datalink_val_to_name(dlt) : "?");
    }

    g_dumper = pcap_dump_open(handle, g_opt.outfile.c_str());
    if (!g_dumper) {
        fprintf(stderr, "pcap_dump_open(%s) failed: %s\n",
                g_opt.outfile.c_str(), pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    printf("Слушаю интерфейс %s, сохраняю EAPOL-кадры в %s ...\n",
           g_opt.iface.c_str(), g_opt.outfile.c_str());
    if (g_opt.have_bssid_filter)
        printf("Фильтр по BSSID: %s\n", mac_to_str(g_opt.bssid_filter).c_str());
    printf("Ctrl+C для остановки.\n");

    pcap_loop(handle, -1, handle_packet, reinterpret_cast<u_char *>(handle));

    pcap_dump_close(g_dumper);
    pcap_close(handle);
    return 0;
}
