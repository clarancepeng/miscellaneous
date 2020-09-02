#ifndef EF_VI_RECEIVE2_H_
#define EF_VI_RECEIVE2_H_
#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <arpa/inet.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <cstring>
#include <unistd.h>
#include "utils.h"

#ifndef MAP_HUGETLB
/* Not always defined in glibc headers.  If the running kernel does not
 * understand this flag it will ignore it and you may not get huge pages.
 * (In that case ef_memreg_alloc() may fail when using packed-stream mode).
 */
#define MAP_HUGETLB 0x40000
#endif
#define EV_POLL_BATCH_SIZE 16

class EfviReceiver
{
public:
    const char *getLastError() { return last_error_; };

    bool isClosed() { return dh < 0; }

protected:
    bool init(const char *interface)
    {
        int rc;
        if ((rc = ef_driver_open(&dh)) < 0)
        {
            saveError("ef_driver_open failed", rc);
            return false;
        }
        if ((rc = ef_pd_alloc_by_name(&pd, dh, interface, EF_PD_DEFAULT)) < 0)
        {
            saveError("ef_pd_alloc_by_name failed", rc);
            return false;
        }

        int vi_flags = EF_VI_FLAGS_DEFAULT;

        if ((rc = ef_vi_alloc_from_pd(&vi, dh, &pd, dh, -1, N_BUF + 1, 0, NULL, -1, (enum ef_vi_flags)vi_flags)) < 0)
        {
            saveError("ef_vi_alloc_from_pd failed", rc);
            return false;
        }

        size_t alloc_size = N_BUF * PKT_BUF_SIZE;
        buf_mmapped = true;
        pkt_bufs = (char *)mmap(NULL, alloc_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB, -1, 0);
        if (pkt_bufs == MAP_FAILED)
        {
            buf_mmapped = false;
#if __linux__
            rc = posix_memalign((void **)&pkt_bufs, 4096, alloc_size);
            if (rc != 0)
            {
                saveError("posix_memalign failed", -rc);
                return false;
            }
#endif
        }
        if ((rc = ef_memreg_alloc(&memreg, dh, &pd, dh, pkt_bufs, alloc_size) < 0))
        {
            saveError("ef_memreg_alloc failed", rc);
            return false;
        }

        for (int i = 0; i < N_BUF; i++)
        {
            struct pkt_buf *pkt_buf = (struct pkt_buf *)(pkt_bufs + i * PKT_BUF_SIZE);
            pkt_buf->post_addr =
                ef_memreg_dma_addr(&memreg, i * PKT_BUF_SIZE) + 64; // reserve a cache line for saving ef_addr...
            if ((rc = ef_vi_receive_post(&vi, pkt_buf->post_addr, i)) < 0)
            {
                saveError("ef_vi_receive_post failed", rc);
                return false;
            }
        }
        return true;
    }

    bool addFilterSpec(const char *dest_ip, uint16_t dest_port)
    {
        int rc;
        ef_filter_spec filter_spec;
        struct sockaddr_in sa_local;
        sa_local.sin_port = htons(dest_port);
        inet_pton(AF_INET, dest_ip, &(sa_local.sin_addr));
        ef_filter_spec_init(&filter_spec, EF_FILTER_FLAG_NONE);
        if ((rc = ef_filter_spec_set_ip4_local(&filter_spec, IPPROTO_UDP, sa_local.sin_addr.s_addr, sa_local.sin_port)) <
            0)
        {
            saveError("ef_filter_spec_set_ip4_local failed", rc);
            return false;
        }
        if ((rc = ef_vi_filter_add(&vi, dh, &filter_spec, NULL)) < 0)
        {
            saveError("ef_vi_filter_add failed", rc);
            return false;
        }
    }

    void saveError(const char *msg, int rc)
    {
        snprintf(last_error_, sizeof(last_error_), "%s %s", msg, rc < 0 ? (const char *)strerror(-rc) : "");
    }

    void close()
    {
        if (dh >= 0)
        {
            ef_driver_close(dh);
            dh = -1;
        }
        if (pkt_bufs)
        {
            if (buf_mmapped)
            {
                munmap(pkt_bufs, N_BUF * PKT_BUF_SIZE);
            }
            else
            {
                free(pkt_bufs);
            }
            pkt_bufs = nullptr;
        }
    }

    static inline uint16_t ShortFromLE(const char *data)
    {
        return ((uint16_t)(data[0] & 0xFF)) |
               ((uint16_t)((unsigned char)data[1]) << 8);
    }

    static inline uint32_t IntFromLE(const char *data)
    {
        return ((uint32_t)(data[0] & 0xFF)) |
               ((uint32_t)((unsigned char)data[1]) << 8) |
               ((uint32_t)((unsigned char)data[2]) << 16) |
               ((uint32_t)((unsigned char)data[3]) << 24);
    }

    static inline uint64_t LongFromLE(const char *data)
    {
        return ((uint64_t)(data[0] & 0xFF)) |
               ((uint64_t)((unsigned char)data[1]) << 8) |
               ((uint64_t)((unsigned char)data[2]) << 16) |
               ((uint64_t)((unsigned char)data[3]) << 24) |
               ((uint64_t)((unsigned char)data[4]) << 32) |
               ((uint64_t)((unsigned char)data[5]) << 40) |
               ((uint64_t)((unsigned char)data[6]) << 48) |
               ((uint64_t)((unsigned char)data[7]) << 56);
    }

    static const int N_BUF = 512;
    static const int PKT_BUF_SIZE = 2048;
    struct pkt_buf
    {
        ef_addr post_addr;
    };

    struct ef_vi vi;
    char *pkt_bufs = nullptr;

    ef_driver_handle dh = -1;
    struct ef_pd pd;
    struct ef_memreg memreg;
    bool buf_mmapped;
    char last_error_[64] = "";
};

class EfviEthReceiver : public EfviReceiver
{
public:
    bool init(const char *interface, MarketDataService *market_data_service)
    {
        market_data_service_ = market_data_service;
        if (!EfviReceiver::init(interface))
        {
            return false;
        }

        rx_prefix_len = ef_vi_receive_prefix_len(&vi);

        /*
        int rc;
        ef_filter_spec fs;
        ef_filter_spec_init(&fs, EF_FILTER_FLAG_NONE);
        if ((rc = ef_filter_spec_set_port_sniff(&fs, 1)) < 0)
        {
            saveError("ef_filter_spec_set_port_sniff failed", rc);
            return false;
        }
        if ((rc = ef_vi_filter_add(&vi, dh, &fs, NULL)) < 0)
        {
            saveError("ef_vi_filter_add failed", rc);
            return false;
        }
        */
        return true;
    }

    bool addFilterSpec(const char *dest_ip, uint16_t dest_port)
    {
        int rc;
        ef_filter_spec filter_spec;
        struct sockaddr_in sa_local;
        sa_local.sin_port = htons(dest_port);
        inet_pton(AF_INET, dest_ip, &(sa_local.sin_addr));
        ef_filter_spec_init(&filter_spec, EF_FILTER_FLAG_NONE);
        if ((rc = ef_filter_spec_set_ip4_local(&filter_spec, IPPROTO_UDP, sa_local.sin_addr.s_addr, sa_local.sin_port)) <
            0)
        {
            saveError("ef_filter_spec_set_ip4_local failed", rc);
            return false;
        }
        if ((rc = ef_vi_filter_add(&vi, dh, &filter_spec, NULL)) < 0)
        {
            saveError("ef_vi_filter_add failed", rc);
            return false;
        }
    }

    bool addSubscribeGroup(const char *dest_ip)
    {
        if ((subscribe_fd_ = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        {
            saveError("socket failed", -errno);
            return false;
        }

        struct ip_mreq mc_group_;
        mc_group_.imr_multiaddr.s_addr = inet_addr(dest_ip);
        mc_group_.imr_interface.s_addr = INADDR_ANY;
        //inet_addr("192.168.92.199");
        if (setsockopt(subscribe_fd_, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mc_group_, sizeof(mc_group_)) < 0)
        {
            printf("[UdpClient]Adding multicast group error");
            //close(subscribe_fd_);
            // close("Adding multicast group error");
            close();
            exit(1);
        }
        else
            printf("[UdpClient]Adding multicast group...OK.");

        // inet_pton(AF_INET, subscribe_ip, &(mc_group_.imr_interface));
        // inet_pton(AF_INET, dest_ip, &(mc_group_.imr_multiaddr));
        // if (setsockopt(subscribe_fd_, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mc_group_, sizeof(mc_group_)) < 0)
        // {
        //     saveError("setsockopt IP_ADD_MEMBERSHIP failed", -errno);
        //     return false;
        // }
        return true;
    }

    ~EfviEthReceiver()
    {
        close();
    }

    void close()
    {
        is_running_ = false;
        EfviReceiver::close();
    }

    template <typename Handler>
    bool read(Handler handler)
    {
        ef_event evs;
        if (ef_eventq_poll(&vi, &evs, 1) == 0)
            return false;

        int id = EF_EVENT_RX_RQ_ID(evs);
        struct pkt_buf *pkt_buf = (struct pkt_buf *)(pkt_bufs + id * PKT_BUF_SIZE);
        char *data = (char *)pkt_buf + 64 + rx_prefix_len;
        short len = EF_EVENT_RX_BYTES(evs) - rx_prefix_len;
        handler(data, len);
        ef_vi_receive_post(&vi, pkt_buf->post_addr, id);
        return true;
    }

    void run()
    {
        while (is_running_)
        {
            /*
            ef_event evs[EV_POLL_BATCH_SIZE];
            // ef_request_id ids[EF_VI_RECEIVE_BATCH];
            int i, j, n_rx;

            int n_ev = ef_eventq_poll(&vi, evs, EV_POLL_BATCH_SIZE);

            for (i = 0; i < n_ev; ++i)
            {
                int id = EF_EVENT_RX_RQ_ID(evs[i]);
                struct pkt_buf *pkt_buf = (struct pkt_buf *)(pkt_bufs + id * PKT_BUF_SIZE);
                char *data = (char *)pkt_buf + 64 + rx_prefix_len;
                short len = EF_EVENT_RX_BYTES(evs[i]) - rx_prefix_len;
                if (len < 94)
                {
                    continue;
                }
                short msg_type = ShortFromLE(data + 60);
                if (msg_type != 53)
                {
                    continue;
                }
                market_data_service_->HandlePacket2(data + 42, len - 42);
                ef_vi_receive_post(&vi, pkt_buf->post_addr, id);
            }*/
            read([&](char *data, short len) {
                //printf("len = %d\n", len);
                if (len < 94)
                {
                    return;
                }
                short msg_type = ShortFromLE(data + 60);
                if (msg_type != 53)
                {
                    return;
                }
                market_data_service_->HandlePacket2(data + 42, len - 42);
            });
        }
    }

    void start(uint16_t affinity_cpu)
    {
        is_running_ = true;
        std::thread efvi_recv_thread(&EfviEthReceiver::run, this);
        if (affinity_cpu < std::thread::hardware_concurrency())
        {
            spdlog::info("[EfviEthReceiver]Market data Listener[affinity on cpu {}", affinity_cpu);
            Utils::cpuAffinity(affinity_cpu);
        }
        efvi_recv_thread.detach();
    }

private:
    int rx_prefix_len;
    int subscribe_fd_ = -1;
    MarketDataService *market_data_service_;
    bool is_running_ = true;
};

static inline uint16_t ShortFromLE(const char *data)
{
    return ((uint16_t)(data[0] & 0xFF)) |
           ((uint16_t)((unsigned char)data[1]) << 8);
}

static inline uint32_t IntFromLE(const char *data)
{
    return ((uint32_t)(data[0] & 0xFF)) |
           ((uint32_t)((unsigned char)data[1]) << 8) |
           ((uint32_t)((unsigned char)data[2]) << 16) |
           ((uint32_t)((unsigned char)data[3]) << 24);
}

static inline uint64_t LongFromLE(const char *data)
{
    return ((uint64_t)(data[0] & 0xFF)) |
           ((uint64_t)((unsigned char)data[1]) << 8) |
           ((uint64_t)((unsigned char)data[2]) << 16) |
           ((uint64_t)((unsigned char)data[3]) << 24) |
           ((uint64_t)((unsigned char)data[4]) << 32) |
           ((uint64_t)((unsigned char)data[5]) << 40) |
           ((uint64_t)((unsigned char)data[6]) << 48) |
           ((uint64_t)((unsigned char)data[7]) << 56);
}

/*
int main()
{
    EfviEthReceiver recv;
    //EfviUdpReceiver recv;
    const char *interface = "p3p1";
    recv.init(interface);
    recv.addFilterSpec("239.1.1.3", 51000);
    recv.addFilterSpec("239.1.1.3", 51001);
    recv.addFilterSpec("239.1.1.3", 51002);
    recv.addSubscribeGroup("239.1.1.3");
    while (true)
    {
        recv.read([&](const char *data, uint32_t len) {
            //printf("len = %d\n", len);
            //  if(len < 94) {
            //     return;
            //  }
            printf("len = %d\n", len);

            int i;
            //pthread_mutex_lock(&printf_mutex_);
            for (i = 0; i < len; ++i)
            {
                const char *eos;
                switch (i & 15)
                {
                case 0:
                    printf("%08x  ", i);
                    eos = "";
                    break;
                case 1:
                    eos = " ";
                    break;
                case 15:
                    eos = "\n";
                    break;
                default:
                    eos = (i & 1) ? " " : "";
                    break;
                }
                printf("%02x%s", (unsigned)(data[i] & 0xFF), eos);
            }

            printf(((len & 15) == 0) ? "\n" : "\n\n");

            //});

            short msg_type = ShortFromLE(data + 60);
            if (msg_type != 53)
            {
                return;
            }
            /*
        short pos = 42;
        short pack_len = ShortFromLE(data + pos);
        pos += 16;
        short msg_len = ShortFromLE(data + pos);
        pos += 2; // msg_len
        // short msg_type = ShortFromLE(data + pos);
        pos += 2; // msg_type
        //spdlog::info("********* msg_len = {}, msg_type = {}", msg_len, msg_type);
        int security_id = IntFromLE(data + pos);
        int bid1 = 0, ask1 = 0, bid_size1 = 0, ask_size1 = 0;
        pos += 7; // security_id + filter
        uint8_t no_entities = data[pos++] & 0xFF;
        bool has_bid = false, has_offer = false;
        for (int i = 0; i < no_entities; i++)
        {
            short side = ShortFromLE(data + pos + 16);
            uint8_t price_level = data[pos + 18] & 0xFF;
            if (price_level == 1)
            {
                if (side == 0)
                {
                    //buy
                    bid_size1 = LongFromLE(data + pos);
                    bid1 = IntFromLE(data + pos + 8);
                    if (has_offer)
                        break;
                    has_bid = true;
                }
                else if (side == 1)
                {
                    //offer
                    ask_size1 = LongFromLE(data + pos);
                    ask1 = IntFromLE(data + pos + 8);
                    if (has_bid)
                        break;
                    has_offer = true;
                }
            }
            pos += 24;
        }
        if (bid1 > 0 || ask1 > 0)
        {
           printf("quote: security_id=%d, bid=%d, ask=%d, bid_size=%d, ask_size=%d", security_id, bid1, ask1, bid_size1, ask_size1);
        }
        
        });
    }

    return 0;
}
*/
#endif // EF_VI_RECEIVE2_H_
