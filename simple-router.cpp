/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
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

//server mac address 32:86:A1:1E:6B:3D

#include "simple-router.hpp"
#include "core/utils.hpp"
#include <iostream>
#include <fstream>
#include "string.h"
namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface, int nat_flag)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;
   
  // FILL THIS IN
  ethernet_hdr hd;
  //std::cout<<"new packet\n";
  const uint8_t* buf = packet.data();
  print_hdr_eth(buf);
  //ethernet_hdr* hd= (ethernet_hdr*) packet;
  for (int i=0; i<6;i++)
  {
      hd.ether_dhost[i] = packet[i];
      hd.ether_shost[i] = packet[i+6];
  }
  //std::cout<<int(packet[12]);
  //std::cout<<int(packet[13]);
  hd.ether_type = (packet[12] << 8) + packet[13];
  int broadcastFlag = 0;
  int MACflag = 0;
  for (int i = 0; i<6;i++)
  {
      if (hd.ether_dhost[i] != 0xFF)
          broadcastFlag= 1;
  }
  for (int i = 0; i<6;i++)
  {
      if (hd.ether_dhost[i]!=iface->addr[i])
          MACflag= 1;
  }


  //std::cout << hd.ether_type;
  if (hd.ether_type != 0x0806 && hd.ether_type != 0x0800)
  {
      //std::cout << "do nothing?\n";
  }
  else if (broadcastFlag==1 && MACflag ==1 )
  {
      //std::cout << "do nothing \n";
  }
  else
  {
    //std::cout << "did something";
    //const Interface* destIface = findIfaceByMac(hd.ether_dhost);
    sendPacket(packet, inIface);     
    
    if(hd.ether_type == 0x0806) //if arp
    {
      const uint8_t* buf = packet.data();
      buf+=sizeof(hd);
      //print_hdr_arp(buf); 
      arp_hdr* arpHd = (arp_hdr*)buf;
      fprintf(stdout, "\thardware type: %d\n", ntohs(arpHd->arp_hrd));
      //check arp-cache
      if (0x0001 == ntohs(arpHd->arp_op)) //if arp request
      {
        //arp request
        //unsigned char macAddr[6]; 
        //std::cout << "\n mac addr:";
        for(int i = 0; i<6; i++)
        {
          (arpHd->arp_tha)[i] = (arpHd->arp_sha)[i];
          (arpHd->arp_sha)[i] = (iface->addr)[i];

          //std::cout << macAddr[i];
        }
        uint16_t tmp = arpHd->arp_sip;
        arpHd->arp_sip = arpHd->arp_tip;
        arpHd->arp_tip = tmp;
        arpHd->arp_op =  htons(0x0002); //setting type to arp reply
        sendPacket(packet, inIface);//?
        //print_hdr_arp(buf);
        
      }
      else if (0x0002 == ntohs(arpHd->arp_op))
      {
       // fprintf(stdout, "\n it was an arp reply\n");
        std::vector<unsigned char> macBuffer;
        for (int i =0; i<6; i++)
        {
          macBuffer.push_back((arpHd->arp_sha)[i]);
        }

        const std::vector<unsigned char> conBuffer(macBuffer); 
//do lookup first i think???
        //code in arp-cache.cpp
        std::shared_ptr<simple_router::ArpRequest> requests = m_arp.insertArpEntry(conBuffer, arpHd->arp_sip);
        if(requests!=nullptr)
        {
          //fprintf(stdout, "\nGot some requests to do\n");
          std::list<simple_router::PendingPacket> packetList = requests->packets;
          std::list<simple_router::PendingPacket>::iterator it;
          for(it = packetList.begin(); it != packetList.end(); ++it)
          {
            //std::cout << "in the list";
            //const Interface* outIface = findIfaceByName(it->iface);
            ethernet_hdr* urmum = (ethernet_hdr*) it->packet.data();
            auto iface = findIfaceByName(it->iface);  
            for(int i=0; i<6; i++)
            {
              urmum->ether_dhost[i] = iface->addr[i];
            }
            handlePacket(it->packet, it->iface, nat_flag);
            const uint8_t* buf = packet.data();
            buf+=sizeof(hd);
            print_hdr_arp(buf); 
          }    
          m_arp.removeRequest(requests);      
        }
      }
    
    }
    else
    {
      //std::cout<<"\n got an IP packet \n";

      //check if ip address is you
      // if it is you, check if icmp 

      const uint8_t* buf = packet.data();
      buf+=sizeof(hd);
      print_hdr_ip(buf);
      ip_hdr* ipHd = (ip_hdr*)buf;
      uint16_t oldsum = ipHd->ip_sum;
      ipHd->ip_sum=0;
      uint16_t newsum = cksum(buf, sizeof(ip_hdr));
      if (oldsum==newsum)
      {
        //std::cout <<"\n ip checksum passed\n";
        ipHd->ip_sum = newsum;
        if(iface->ip == ipHd->ip_dst) //if ip is your ip
        {
          //std::cout<<"\ndestined to router \n";

          if(ipHd->ip_p == ip_protocol_icmp)          //if icmp packet-> hndle ping
          {
            //struct icmp_hdr icmpPacket;
            const uint8_t* icmpBuf = packet.data();
            icmpBuf+=sizeof(ethernet_hdr)+sizeof(ip_hdr);
            icmp_hdr* icmpPacket = (icmp_hdr*)icmpBuf;
            if(icmpPacket->icmp_type==8)
            {
              //we got an icmp echo message
              uint16_t oldICMPsum = icmpPacket->icmp_sum;
              icmpPacket->icmp_sum = 0;
              //icmp checksum uses data as well
              int len = ntohs(ipHd->ip_len) - sizeof(ip_hdr);
              uint16_t icmpCheck = cksum(icmpPacket, len);

              if(oldICMPsum != icmpCheck)
              {
                //checksum failed
                //std::cout << "icmp checksum failed\n";
                return;
              }
              else 
              {

                //echo requests sent to other ip addresses should be forwarded to next hop address
                //send echo reply; 
                //look up mac address in arpcache; 
                //     if nullptr queue packet for later using enqueue
                //      if not nullptr, then you have the new mac address. sender mac address is ur mac address from interface var 
                //          .use that as the dest and change from echo type to echro reply type and then handle packet

                //if targetIP's interface= inIface then make echo reply
                
                if(!true)
                {
                  //std::cout<<"wtf\n";
                }
                if(m_arp.lookup(ipHd->ip_src)==nullptr) //if mac address note in arpcache
                {
                  //queue packet
                  //std::cout<<"why is this stopping tcp socket from dropping\n";
                  Buffer senderMac = std::vector<unsigned char>(6, 0);
                  memcpy(&senderMac[0], &packet[6], 6);
                  m_arp.insertArpEntry(senderMac ,ipHd->ip_src);
                }
                //otherwise, we have the new mac address
                else
                {
                  //std::cout << "using next hop to forward and icmp passed\n";

                  ip_hdr* urdad = (ip_hdr*) (packet.data()+sizeof(ethernet_hdr));
                  auto tempAddr = urdad->ip_dst;
                  urdad->ip_dst = urdad->ip_src;
                  urdad->ip_src = tempAddr;  
                  RoutingTableEntry match = m_routingTable.lookup(ipHd->ip_dst);
                  std::shared_ptr<simple_router::ArpEntry> destMac;
                  destMac = m_arp.lookup(match.gw);
                  if(destMac==nullptr)
                  {
                    //std::cout<<"queueing request\n";
                    const uint8_t* buf = packet.data();
                    print_hdrs(buf, sizeof(ethernet_hdr)+sizeof(ip_hdr)+sizeof(icmp_hdr));
                    m_arp.queueRequest(ipHd->ip_dst, packet, match.ifName);
                  }
                  else
                  {
                    const Interface *ifaceForward = findIfaceByName(match.ifName);

                    ethernet_hdr* urmum = (ethernet_hdr*) packet.data();
                    memcpy(urmum->ether_shost, &ifaceForward->addr[0] ,sizeof(hd.ether_shost));
                    //memcpy(hd.ether_dhost, (destMac->mac).data(), sizeof(hd.ether_dhost));
                    for(int i=0; i<6; i++)
                    {
                      urmum->ether_dhost[i] = destMac->mac[i];
                    }

                    

                    icmpPacket->icmp_type=0; 
                    icmpPacket->icmp_sum=0;
                    urdad->ip_sum=0;

                    const uint8_t* buf = packet.data();
                    print_hdr_eth(buf);
                    buf+=sizeof(ethernet_hdr);
                    
                    urdad->ip_sum=cksum(buf, sizeof(ip_hdr));
                    print_hdr_ip(buf);
                    buf+=sizeof(ip_hdr);

                    icmpPacket->icmp_sum=cksum(buf, sizeof(icmp_hdr));

                    print_hdr_icmp(buf);
                    buf+=sizeof(hd);
                    //std::cout<<"about to send packet after icmp update\n";
                    sendPacket(packet, ifaceForward->name); 
                  }

                }


                //recompute checksum. the ip or icmp?

              }

            }
          }
          //else does not carry icmp payload, just discard 
        }
        else //if ip address belongs to someone else, do ip forwarding
        {
          //std::cout << "\nip address is not mine, do ip forwarding \n";
          //translate if NAT
          ipHd->ip_ttl=(ipHd->ip_ttl)-1;

          if(ipHd->ip_ttl==0)
          {
            //ttl is 0
            //std::cout << "ttl is 0\n";
            return;
          }
          else //valid ttl
          {
            //std::cout << "ttl is valid\n";
            //uint16_t oldsum2 = ipHd->ip_sum;
            ipHd->ip_sum = 0;
            ipHd->ip_sum = cksum(buf, sizeof(ip_hdr)); 

            //std::cout << "passed ip checksum\n";
            if(findIfaceByIp(ipHd->ip_dst) != nullptr)
            {
              //std::cout << "found ip on interface so just sent packet\n";
              const Interface* sendingIface = findIfaceByIp(ipHd->ip_dst);
              ethernet_hdr* urmum = (ethernet_hdr*) packet.data();
              for(int i=0; i<6;i++)
              {
                urmum->ether_dhost[i]=sendingIface->addr[i];
              }
              //std::cout<<"sendingpacket2\n";
              handlePacket(packet, sendingIface->name,nat_flag);
              
            }
            //lookup routing table and find next hop
            else
            {
              RoutingTableEntry match = m_routingTable.lookup(ipHd->ip_dst);

              //look up arp cache 
              //const uint8_t* buf2 = packet.data();
              //print_hdr_arp(buf2);

              if(m_arp.lookup(ipHd->ip_dst)==nullptr) //if mac address not found do the queue
              {
                //std::cout << "arp entry not found, forwarding packet\n";
                //arp entry not found, forward the packet
                //std::vector<unsigned char> temp = std::vector<unsigned char>(6,0);
                //std::memcpy(&temp[0],&hd.ether_dhost,sizeof(hd.ether_dhost));
                ///const std::vector<unsigned char> msgEthAddr = temp;
                //const Interface *msgInter = findIfaceByMac(msgEthAddr);
                //
                m_arp.queueRequest(ipHd->ip_dst, packet, match.ifName);
                //send arp req
              }
              else //make the mac address the destination mac address and handle packet with next hop stuff
              {
                //std::cout << "using next hop to forward\n";

                std::shared_ptr<simple_router::ArpEntry> destMac;
                destMac = m_arp.lookup(match.gw);
                const Interface *ifaceForward = findIfaceByName(match.ifName);
                ethernet_hdr* urmum = (ethernet_hdr*) packet.data();
                
                memcpy(urmum->ether_shost, &ifaceForward->addr[0] ,sizeof(hd.ether_shost));
                //memcpy(hd.ether_dhost, (destMac->mac).data(), sizeof(hd.ether_dhost));
                for(int i=0; i<6; i++)
                {
                  urmum->ether_dhost[i] = (destMac->mac)[i];
                }
                
                const uint8_t* buf = packet.data();
                print_hdr_eth(buf);
                buf+=sizeof(hd);
                print_hdr_ip(buf);
                //std::cout<<"sending1\n";
                sendPacket(packet, ifaceForward->name);
              }
            }
          }
        }
      }
      else
      {
        //std::cout << "failed checksum";
      }
    }

  }   
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
  , m_natTable(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {
