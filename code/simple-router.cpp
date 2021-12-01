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

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router
{
    const Buffer SimpleRouter::BROADCAST_ADDR{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    Buffer SimpleRouter::formEtherPacket(const Buffer &dst, const Buffer &src, uint16_t type,
                                         const Buffer::const_iterator &ether_payload_beg,
                                         const Buffer::const_iterator &ether_payload_end)
    {
        ethernet_hdr ether_h;
        memcpy(ether_h.ether_dhost, dst.data(), dst.size() * sizeof(dst[0]));
        memcpy(ether_h.ether_shost, src.data(), src.size() * sizeof(src[0]));
        ether_h.ether_type = htons(type);
        auto buffer = Buffer((uint8_t *)&ether_h, (uint8_t *)&ether_h + sizeof(ether_h));
        buffer.insert(buffer.end(), ether_payload_beg, ether_payload_end);
        return buffer;
    }

    void SimpleRouter::handleArp(const arp_hdr *arp_h)
    {
        if (ntohs(arp_h->arp_op) == arp_op_request)
        {
            // Find targeting iface
            auto dest_iface = findIfaceByIp(arp_h->arp_tip);
            if (!dest_iface)
            {
                std::cerr << "Received ARP Request targeting " << ipToString(arp_h->arp_tip) << " which is not here, ignoring" << std::endl;
                return;
            }
            auto &dest_addr = dest_iface->addr;

            fprintf(stderr, "handleArp requesting %s %s %s\n", dest_iface->name.data(), macToString(dest_iface->addr).data(), ipToString(dest_iface->ip).data());

            // Fill and send ARP reply
            Buffer reply_arp_pkg(sizeof(arp_hdr));
            auto reply_arp_h = (arp_hdr *)reply_arp_pkg.data();
            reply_arp_h->arp_hrd = htons(arp_hrd_ethernet);
            reply_arp_h->arp_pro = htons(ethertype_ip);
            reply_arp_h->arp_hln = 6;
            reply_arp_h->arp_pln = 4;
            reply_arp_h->arp_op = htons(arp_op_reply);
            reply_arp_h->arp_sip = arp_h->arp_tip;
            reply_arp_h->arp_tip = arp_h->arp_sip;
            memcpy(reply_arp_h->arp_sha, dest_addr.data(), 6);
            memcpy(reply_arp_h->arp_tha, arp_h->arp_sha, 6);

            auto packet = formEtherPacket(Buffer(reply_arp_h->arp_tha, reply_arp_h->arp_tha + 6),
                                          Buffer(reply_arp_h->arp_sha, reply_arp_h->arp_sha + 6),
                                          ethertype_arp,
                                          reply_arp_pkg.begin(),
                                          reply_arp_pkg.end());
            auto out_iface = getRoutingTable().lookup(reply_arp_h->arp_tip).ifName;
            fprintf(stderr, "handleArp send response to %s\n", out_iface.data());
            sendPacket(packet, out_iface);
        }
        else
        {
            // Extract source MAC address
            Buffer needed_mac((uint8_t *)arp_h->arp_sha, (uint8_t *)arp_h->arp_sha + 6);
            fprintf(stderr, "handleArp response: %s %s\n",
                    macToString(needed_mac).c_str(),
                    ipToString(arp_h->arp_sip).c_str());

            // Get request and send queued packets
            auto arp_request = m_arp.insertArpEntry(needed_mac, arp_h->arp_sip);
            if (arp_request != nullptr)
            {
                for (auto &p : arp_request->packets)
                {
                    auto ether_h = (ethernet_hdr *)p.packet.data();
                    memcpy(ether_h->ether_dhost, needed_mac.data(), 6); // Fill in destination MAC
                    sendPacket(p.packet, p.iface);
                }
                m_arp.removeRequest(arp_request);
            }
        }
    }

    Buffer SimpleRouter::formIcmpType3(const Interface *iface,
                                       const ip_hdr *src_ip_h,
                                       const Buffer::const_iterator &src_payload_beg,
                                       uint8_t type,
                                       uint8_t code)
    {
        Buffer packet(20 + sizeof(icmp_t3_hdr), 0);
        auto ip_h = (ip_hdr *)packet.data();
        auto hdr = (icmp_t3_hdr *)(packet.data() + 20);

        // Fill ICMP header
        hdr->icmp_code = code;
        hdr->icmp_type = type;
        memcpy(hdr->data, (uint8_t *)src_ip_h, 20);
        memcpy(hdr->data + 20, &(*src_payload_beg), 8);
        auto sum = cksum(packet.begin() + 20, packet.end());
        hdr->icmp_sum = sum;

        // Fill IP header
        ip_h->ip_v = 4;
        ip_h->ip_hl = 5;
        ip_h->ip_tos = 0;
        ip_h->ip_len = htons(uint16_t(packet.size()));
        ip_h->ip_id = htons((uint16_t)rand());
        ip_h->ip_off = htons(IP_DF);
        ip_h->ip_ttl = 64;
        ip_h->ip_p = ip_protocol_icmp;
        ip_h->ip_src = iface->ip;
        ip_h->ip_dst = src_ip_h->ip_src;
        auto ip_sum = cksum(packet.begin(), packet.begin() + 20);
        ip_h->ip_sum = ip_sum;

        return packet;
    }

    Buffer SimpleRouter::formIcmpEcho(const Interface *iface,
                                      const ip_hdr *src_ip_h,
                                      const Buffer::const_iterator &src_payload_beg,
                                      const Buffer::const_iterator &src_payload_end)
    {
        Buffer packet(20, 0);
        packet.insert(packet.end(), src_payload_beg, src_payload_end);
        auto ip_h = (ip_hdr *)packet.data();
        auto hdr = (icmp_echo_hdr *)(packet.data() + 20);

        // Change ICMP header
        hdr->icmp_type = 0;
        hdr->icmp_sum = 0;
        auto sum = cksum(packet.begin() + 20, packet.end());
        hdr->icmp_sum = sum;

        // Fill IP header
        ip_h->ip_v = 4;
        ip_h->ip_hl = 5;
        ip_h->ip_tos = 0;
        ip_h->ip_len = htons(uint16_t(packet.size()));
        ip_h->ip_id = htons((uint16_t)rand());
        ip_h->ip_off = htons(IP_DF);
        ip_h->ip_ttl = 64;
        ip_h->ip_p = ip_protocol_icmp;
        ip_h->ip_src = iface->ip;
        ip_h->ip_dst = src_ip_h->ip_src;
        auto ip_sum = cksum(packet.begin(), packet.begin() + 20);
        ip_h->ip_sum = ip_sum;

        return packet;
    }

    void SimpleRouter::handleIp(const ip_hdr *ip_h,
                                const Buffer::const_iterator &payload_beg,
                                const Buffer::const_iterator &payload_end,
                                const std::string &in_iface)
    {
        auto dst_ip = ip_h->ip_dst;

        // Initialized packet to be send, copying IP header
        Buffer ether_payload((uint8_t *)ip_h, (uint8_t *)ip_h + 20);
        auto cp_h = (ip_hdr *)ether_payload.data();
        cp_h->ip_sum = 0;

        // Checksum
        auto calc_sum = cksum(ether_payload.begin(), ether_payload.begin() + 20);
        fprintf(stderr, "handleIp checksum comp %d orig %d\n", calc_sum, ip_h->ip_sum);
        if (calc_sum != ip_h->ip_sum)
        {
            fprintf(stderr, "Received IP packet with error checksum, ignore\n");
            return;
        }

        auto local_if = findIfaceByIp(dst_ip);
        Buffer icmp;

        if ((local_if && ip_h->ip_ttl == 0) || (!local_if && ip_h->ip_ttl == 1))
        {
            // Timeout
            fprintf(stderr, "handleIp zero TTL\n");
            icmp = formIcmpType3(findIfaceByName(in_iface), ip_h, payload_beg, 11, 0);
        }
        else if (local_if)
        {
            // Local packet
            if (ip_h->ip_p != ip_protocol_icmp)
            {
                if (ip_h->ip_p == ip_protocol_tcp || ip_h->ip_p == ip_protocol_udp)
                {
                    fprintf(stderr, "handleIp TCP/UDP towards router\n");
                    icmp = formIcmpType3(findIfaceByName(in_iface), ip_h, payload_beg, 3, 3);
                }
                else
                {
                    fprintf(stderr, "Received IP packet towards router with non-ICMP/TCP/UDP protocol, ignore\n");
                    return;
                }
            }
            else
            {
                auto echo_h = (icmp_echo_hdr *)&(*payload_beg);
                // Check if it is an echo request / reply
                if (echo_h->icmp_type == 8 && echo_h->icmp_code == 0)
                {
                    fprintf(stderr, "handleIp ICMP echo\n");
                    icmp = formIcmpEcho(findIfaceByName(in_iface), ip_h, payload_beg, payload_end);
                }
                else
                {
                    fprintf(stderr, "Received invalid ICMP packet, ignore\n");
                    return;
                }
            }
        }
        else
        {
            // Forward packet
            fprintf(stderr, "handleIp foward\n");
            --cp_h->ip_ttl;
            auto new_sum = cksum(ether_payload.begin(), ether_payload.begin() + 20);
            cp_h->ip_sum = new_sum;
            ether_payload.insert(ether_payload.end(), payload_beg, payload_end);
        }
        if (icmp.size() != 0)
        {
            // Replace packet with formed ICMP packet
            ether_payload.clear();
            ether_payload.insert(ether_payload.begin(), icmp.begin(), icmp.end());
            dst_ip = ip_h->ip_src;
        }
        sendIp(dst_ip, ether_payload.begin(), ether_payload.end(), in_iface, ip_h);
    }

    void SimpleRouter::sendIp(uint32_t dst_ip,
                              const Buffer::const_iterator &ether_payload_beg,
                              const Buffer::const_iterator &ether_payload_end,
                              const std::string &in_iface,
                              const ip_hdr *orig_ip_h)
    {
        auto out_iface = findIfaceByName(getRoutingTable().lookup(dst_ip).ifName);
        fprintf(stderr, "sendIp out iface %s\n", out_iface->name.c_str());

        auto dst_arp_entry = m_arp.lookup(dst_ip);
        if (!dst_arp_entry)
        {
            // No ARP entry, queue packet
            fprintf(stderr, "sendIp to %s queued\n", ipToString(dst_ip).c_str());
            auto packet = formEtherPacket(
                Buffer{0, 0, 0, 0, 0, 0},
                out_iface->addr,
                ethertype_ip,
                ether_payload_beg,
                ether_payload_end);
            m_arp.queueRequest(dst_ip, packet, out_iface->name, in_iface, *orig_ip_h);
        }
        else
        {
            // ARP entry found, send packet
            fprintf(stderr, "sendIp to %s sending now\n", ipToString(dst_ip).c_str());
            auto packet = formEtherPacket(
                dst_arp_entry->mac,
                out_iface->addr,
                ethertype_ip,
                ether_payload_beg,
                ether_payload_end);
            sendPacket(packet, out_iface->name);
        }
    }

    //////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////
    // IMPLEMENT THIS METHOD
    void SimpleRouter::handlePacket(const Buffer &packet, const std::string &inIface)
    {
        std::cerr << "--------------------\nGot packet of size " << packet.size() << " on interface " << inIface << std::endl;
        print_hdrs(packet);

        const Interface *iface = findIfaceByName(inIface);
        if (iface == nullptr)
        {
            std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
            return;
        }

        auto ether_h = (const ethernet_hdr *)packet.data();

        Buffer ether_dhost((uint8_t *)ether_h->ether_dhost, (uint8_t *)ether_h->ether_dhost + 6);
        auto dst_iface = findIfaceByMac(ether_dhost);
        if (ether_dhost != BROADCAST_ADDR && !dst_iface)
        {
            std::cerr << "Received packet not destined to router but " << macToString(ether_dhost) << ", ignoring" << std::endl;
            return;
        }

        auto ether_type = ntohs(ether_h->ether_type);
        if (ether_type != ethertype_arp && ether_type != ethertype_ip)
        {
            std::cerr << "Received packet with type " << ether_type << ", ignoring" << std::endl;
            return;
        }

        auto header_ptr = packet.data() + 14;
        if (ether_type == ethertype_arp)
            handleArp((const arp_hdr *)header_ptr);
        else
            handleIp((const ip_hdr *)header_ptr, packet.begin() + 34, packet.end(), inIface);
    }
    //////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////

    // You should not need to touch the rest of this code.
    SimpleRouter::SimpleRouter()
        : m_arp(*this)
    {
        srand(time(NULL));
    }

    void SimpleRouter::sendPacket(const Buffer &packet, const std::string &outIface)
    {
        fprintf(stderr, "Sending packet on %s with MAC %s\n", outIface.data(), macToString(findIfaceByName(outIface)->addr).data());
        print_hdrs(packet);
        m_pox->begin_sendPacket(packet, outIface);
    }

    bool SimpleRouter::loadRoutingTable(const std::string &rtConfig)
    {
        return m_routingTable.load(rtConfig);
    }

    void SimpleRouter::loadIfconfig(const std::string &ifconfig)
    {
        std::ifstream iff(ifconfig.c_str());
        std::string line;
        while (std::getline(iff, line))
        {
            std::istringstream ifLine(line);
            std::string iface, ip;
            ifLine >> iface >> ip;

            in_addr ip_addr;
            if (inet_aton(ip.c_str(), &ip_addr) == 0)
            {
                throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
            }

            m_ifNameToIpMap[iface] = ip_addr.s_addr;
        }
    }

    void SimpleRouter::printIfaces(std::ostream &os)
    {
        if (m_ifaces.empty())
        {
            os << " Interface list empty " << std::endl;
            return;
        }

        for (const auto &iface : m_ifaces)
        {
            os << iface << "\n";
        }
        os.flush();
    }

    const Interface *SimpleRouter::findIfaceByIp(uint32_t ip) const
    {
        auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip](const Interface &iface)
                                  { return iface.ip == ip; });

        if (iface == m_ifaces.end())
        {
            return nullptr;
        }

        return &(*iface);
    }

    const Interface *SimpleRouter::findIfaceByMac(const Buffer &mac) const
    {
        auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac](const Interface &iface)
                                  { return iface.addr == mac; });

        if (iface == m_ifaces.end())
        {
            return nullptr;
        }

        return &(*iface);
    }

    const Interface *SimpleRouter::findIfaceByName(const std::string &name) const
    {
        auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name](const Interface &iface)
                                  { return iface.name == name; });

        if (iface == m_ifaces.end())
        {
            return nullptr;
        }

        return &(*iface);
    }

    void SimpleRouter::reset(const pox::Ifaces &ports)
    {
        std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

        m_arp.clear();
        m_ifaces.clear();

        for (const auto &iface : ports)
        {
            auto ip = m_ifNameToIpMap.find(iface.name);
            if (ip == m_ifNameToIpMap.end())
            {
                std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
                continue;
            }

            m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
        }

        printIfaces(std::cerr);
    }

} // namespace simple_router {
