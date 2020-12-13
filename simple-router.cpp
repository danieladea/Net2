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


  std::cout << hd.ether_type;
  if (hd.ether_type != 0x0806 && hd.ether_type != 0x0800)
      std::cout << "do nothing?\n";
  else if (broadcastFlag==1 && MACflag ==1 )
      std::cout << "do nothing \n";
  else
  {
      std::cout << "did something";
      //const Interface* destIface = findIfaceByMac(hd.ether_dhost);
      sendPacket(packet, inIface);     
  
    if(hd.ether_type == 0x0806)
    {
      const uint8_t* buf = packet.data();
      buf+=sizeof(hd);
      print_hdr_arp(buf); 
      arp_hdr* arpHd = (arp_hdr*)buf;
      fprintf(stdout, "\thardware type: %d\n", ntohs(arpHd->arp_hrd));
      //check arp-cache
      if (0x0001 == ntohs(arpHd->arp_op))
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
        arpHd->arp_op =  htons(0x0002);
        handlePacket(packet, inIface, nat_flag);//?
        print_hdr_arp(buf);
        

      }
      else if (0x0002 == ntohs(arpHd->arp_op))
      {
        fprintf(stdout, "\nshe replied to my dm\n");
        std::vector<unsigned char> macBuffer;
        for (int i =0; i<6; i++)
        {
          macBuffer.push_back((arpHd->arp_sha)[i]);
        }

        const std::vector<unsigned char> conBuffer(macBuffer); 
//do lookup first i think???
        std::shared_ptr<simple_router::ArpRequest> requests = m_arp.insertArpEntry(conBuffer, arpHd->arp_sip);
        if(requests!=nullptr)
        {
          fprintf(stdout, "\nGot some requests to do\n");
          std::list<simple_router::PendingPacket> packetList = requests->packets;
          std::list<simple_router::PendingPacket>::iterator it;
          for(it = packetList.begin(); it != packetList.end(); ++it)
          {
            std::cout << "in the list";
            //const Interface* outIface = findIfaceByName(it->iface);
            handlePacket(it->packet, it->iface, nat_flag);
          }          
        }
        //m_arp.removeRequest();

      }
    
    }
    else
    {
      std::cout<<"\n got an IP packet \n";


      const uint8_t* buf = packet.data();
      buf+=sizeof(hd);
      print_hdr_ip(buf); 
      ip_hdr* ipHd = (ip_hdr*)buf;
      uint16_t oldsum = ipHd->ip_sum;
      ipHd->ip_sum=0;
      uint16_t newsum = cksum(&ipHd, sizeof(ipHd));
      if (oldsum==newsum)
      {
        if(iface->ip == ipHd->ip_dst)
        {
          cout<<"\ndestined to router \n";
        }
        else
        {
          cout << "\nforward packet\n";
          //translate if NAT
          ipHd->ip_ttl=ipHd->ttl-1;
          uint16_t oldsum2 = ipHd->ip_sum;
          ipHd->ip_sum=0;
          uint16_t ipHd->ip
        }
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
