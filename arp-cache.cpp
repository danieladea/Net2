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
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{

  // FILL THIS IN
  // record request after 5 tries.
  std::vector<std::list<std::shared_ptr<ArpRequest>>::iterator> invalidRequests;
  for (auto it = m_arpRequests.begin(); it != m_arpRequests.end(); ++it) 
  {
    if (*it == nullptr) 
    {
      return;
    }

    auto currTime = steady_clock::now();
    if (std::chrono::duration_cast<seconds>(currTime - (*it)->timeSent) >= seconds(1)) 
    {
      if ((*it)->nTimesSent >= 5) 
      {
        std::list<PendingPacket>::iterator packetIterator;
        m_arpRequests.remove(*it);
        return;
      }
      else 
      {
        //send arp request
        Buffer manualPacket(sizeof(arp_hdr) + sizeof (ethernet_hdr));

        struct RoutingTableEntry routeEntry = m_router.getRoutingTable().lookup((*it)->ip);
        const Interface *tableInterface = m_router.findIfaceByName(routeEntry.ifName);
        struct ethernet_hdr ethHd;
        /*for(int i = 0; i<ETHER_ADDR_LEN; i++)
        {
          ethHd.ether_dhost[i]=0xFF;
        }*/
        memcpy(ethHd.ether_dhost,BroadcastEtherAddr,ETHER_ADDR_LEN);
        memcpy(&(ethHd.ether_shost), tableInterface->addr.data(),ETHER_ADDR_LEN);
        ethHd.ether_type = htons(ethertype_arp);

        //do arp now
        struct arp_hdr arpHd;
        arpHd.arp_hrd = htons(arp_hrd_ethernet);
        arpHd.arp_pro = htons(ethertype_ip);
        arpHd.arp_hln = ETHER_ADDR_LEN;
        arpHd.arp_pln = 4;
        arpHd.arp_op = htons(arp_op_request);

        memcpy(arpHd.arp_sha, tableInterface->addr.data(), ETHER_ADDR_LEN);
        arpHd.arp_sip = tableInterface->ip;
        const uint8_t* targHardware[ETHER_ADDR_LEN] = {0x00,0x00,0x00,0x00,0x00,0x00}; //can we do this instead of for loop?
        memcpy(arpHd.arp_tha, targHardware, ETHER_ADDR_LEN);
        arpHd.arp_tip = (*it)->ip;


        memcpy(&manualPacket[0], &ethHd, sizeof(ethernet_hdr));
        memcpy(&manualPacket[sizeof(ethHd)], &arpHd, sizeof(arp_hdr));
        //print_hdrs(manualPacket);
        m_router.sendPacket(manualPacket, tableInterface->name);
        std::cout<< "sent manual packet\n";
      }
    }

  }

  //remove
  std::list<std::shared_ptr<ArpEntry>>::iterator arpIter=m_cacheEntries.begin();
  while(arpIter!=m_cacheEntries.end())
  {
    if(!(*arpIter)->isValid)
    {
      arpIter=m_cacheEntries.erase(arpIter);
    }
    else 
    {
      arpIter++;
    }
  }


}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

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
