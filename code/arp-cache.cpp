/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "arp-cache.hpp"
#include "core/interface.hpp"
#include "core/utils.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router
{

    //////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////
    // IMPLEMENT THIS METHOD
    std::vector<std::tuple<uint32_t, Buffer>> ArpCache::periodicCheckArpRequestsAndCacheEntries()
    {
        std::vector<std::shared_ptr<ArpRequest>> to_remove_requests;
        // Sending ICMP(IP) packets here could request mutex, causing deadlock
        // So queue them and send them later
        std::vector<std::tuple<uint32_t, Buffer>> icmps;

        for (auto request : m_arpRequests)
        {
            if (request->nTimesSent >= 5)
            {
                fprintf(stderr, "ArpCache request for %s 5times\n", ipToString(request->ip).data());

                for (const auto &p : request->packets)
                {
                    fprintf(stderr, "ArpCache queued packet:\n");
                    print_hdrs(p.packet);
                    if (p.in_iface == "")
                    {
                        fprintf(stderr, "ArpCache discarding self source packet\n");
                        continue;
                    }
                    // Form and queue ICMP type 3 packet to sender
                    auto iface = m_router.findIfaceByName(p.in_iface);
                    auto icmp = m_router.formIcmpType3(
                        iface, &p.ip_h,
                        p.packet.begin() + sizeof(ethernet_hdr) + sizeof(ip_hdr),
                        3, 1);
                    icmps.push_back(std::make_tuple((uint32_t)p.ip_h.ip_src, icmp));
                    fprintf(stderr, "ArpCache queued ICMP type 3 to %s\n", ipToString(p.ip_h.ip_src).data());
                }
                to_remove_requests.push_back(request);
            }
            else
            {
                fprintf(stderr, "ArpCache request for %s sending\n", ipToString(request->ip).data());
                ++request->nTimesSent;

                // Form and send ARP request
                auto iface = m_router.findIfaceByName(request->packets.front().iface);
                arp_hdr arp_h{
                    htons(0x0001), htons(0x0800), 0x06, 0x04, htons(1),
                    0, 0, 0, 0, 0, 0, iface->ip,
                    0, 0, 0, 0, 0, 0, request->ip};
                memcpy(&arp_h.arp_sha, iface->addr.data(), iface->addr.size());
                Buffer arp_h_b((char *)&arp_h, (char *)&arp_h + sizeof(arp_h));
                auto arp_packet = m_router.formEtherPacket(
                    m_router.BROADCAST_ADDR,
                    iface->addr,
                    ethertype_arp,
                    arp_h_b.begin(),
                    arp_h_b.end());
                m_router.sendPacket(arp_packet, iface->name);
            }
        }
        for (auto request : to_remove_requests)
            m_arpRequests.remove(request);

        std::vector<std::shared_ptr<ArpEntry>> to_remove_entries;
        for (auto entry : m_cacheEntries)
        {
            if (!entry->isValid)
            {
                fprintf(stderr, "ArpCache entry for %s is no more valid\n", ipToString(entry->ip).data());
                to_remove_entries.push_back(entry);
            }
        }
        for (auto entry : to_remove_entries)
            m_cacheEntries.remove(entry);

        return icmps;
    }
    //////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////

    // You should not need to touch the rest of this code.

    ArpCache::ArpCache(SimpleRouter &router)
        : m_router(router), m_shouldStop(false), m_tickerThread(std::bind(&ArpCache::ticker, this))
    {
    }

    ArpCache::~ArpCache()
    {
        m_shouldStop = true;
        m_tickerThread.join();
    }

    std::shared_ptr<ArpEntry> ArpCache::lookup(uint32_t ip)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        for (const auto &entry : m_cacheEntries)
        {
            if (entry->isValid && entry->ip == ip)
            {
                return entry;
            }
        }

        return nullptr;
    }

    std::shared_ptr<ArpRequest> ArpCache::queueRequest(uint32_t ip,
                                                       const Buffer &packet,
                                                       const std::string &iface,
                                                       const std::string &in_iface,
                                                       const ip_hdr &orig_ip_h)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                                    [ip](const std::shared_ptr<ArpRequest> &request)
                                    {
                                        return (request->ip == ip);
                                    });

        if (request == m_arpRequests.end())
        {
            request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
        }

        // Add the packet to the list of packets for this request
        (*request)->packets.push_back({packet, iface, in_iface, orig_ip_h});
        return *request;
    }

    void ArpCache::removeRequest(const std::shared_ptr<ArpRequest> &entry)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_arpRequests.remove(entry);
    }

    std::shared_ptr<ArpRequest> ArpCache::insertArpEntry(const Buffer &mac, uint32_t ip)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto entry = std::make_shared<ArpEntry>();
        entry->mac = mac;
        entry->ip = ip;
        entry->timeAdded = steady_clock::now();
        entry->isValid = true;
        m_cacheEntries.push_back(entry);

        auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                                    [ip](const std::shared_ptr<ArpRequest> &request)
                                    {
                                        return (request->ip == ip);
                                    });
        if (request != m_arpRequests.end())
        {
            return *request;
        }
        else
        {
            return nullptr;
        }
    }

    void ArpCache::clear()
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        m_cacheEntries.clear();
        m_arpRequests.clear();
    }

    void ArpCache::ticker()
    {
        while (!m_shouldStop)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            std::vector<std::tuple<uint32_t, Buffer>> icmps;

            {
                std::lock_guard<std::mutex> lock(m_mutex);

                auto now = steady_clock::now();

                for (auto &entry : m_cacheEntries)
                {
                    if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO))
                    {
                        entry->isValid = false;
                    }
                }

                icmps = periodicCheckArpRequestsAndCacheEntries();
            }
            // Lock released here, send queued icmp packets
            for (const auto &ituple : icmps)
            {
                auto ip = std::get<0>(ituple);
                const auto &icmp = std::get<1>(ituple);
                ip_hdr tmp_ip_h; // Self sending, actually no need for this
                m_router.sendIp(ip, icmp.begin(), icmp.end(), "", &tmp_ip_h);
            }
        }
    }

    std::ostream &operator<<(std::ostream &os, const ArpCache &cache)
    {
        std::lock_guard<std::mutex> lock(cache.m_mutex);

        os << "\nMAC            IP         AGE                       VALID\n"
           << "-----------------------------------------------------------\n";

        auto now = steady_clock::now();
        for (const auto &entry : cache.m_cacheEntries)
        {

            os << macToString(entry->mac) << "   "
               << ipToString(entry->ip) << "   "
               << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
               << entry->isValid
               << "\n";
        }
        os << std::endl;
        return os;
    }

} // namespace simple_router
