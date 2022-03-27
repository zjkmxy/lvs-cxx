/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2021 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

#include <iostream>

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespaces should be used to prevent/limit name conflicts
namespace examples {

class Producer
{
public:
  void
  run()
  {
    m_face.setInterestFilter("/example/testApp/randomData",
                             std::bind(&Producer::onInterest, this, _1, _2),
                             nullptr, // RegisterPrefixSuccessCallback is optional
                             std::bind(&Producer::onRegisterFailed, this, _1, _2));

    auto cert = m_keyChain.getPib().getDefaultIdentity().getDefaultKey().getDefaultCertificate();
    m_certServeHandle = m_face.setInterestFilter(security::extractIdentityFromCertName(cert.getName()),
                             [this, cert] (auto&&...) {
                               m_face.put(cert);
                             },
                             std::bind(&Producer::onRegisterFailed, this, _1, _2));
    m_face.processEvents();
  }

private:
  void
  onInterest(const InterestFilter&, const Interest& interest)
  {
    std::cout << ">> I: " << interest << std::endl;

    static const std::string content("Hello, world!");

    // Create Data packet
    auto data = make_shared<Data>(interest.getName());
    data->setFreshnessPeriod(10_s);
    data->setContent(reinterpret_cast<const uint8_t*>(content.data()), content.size());

    // in order for the consumer application to be able to validate the packet, you need to setup
    // the following keys via pyndnsec
    // 1. Generate example trust anchor
    //
    //         pyndnsec New-Item /example
    //         pyndnsec Export-Cert /example > example-trust-anchor.cert
    //
    // 2. Create a key for the producer and sign it with the example trust anchor
    //
    //         pyndnsec New-Item /example/testApp
    //         pyndnsec Get-SignReq /example/testApp | pyndnsec Sign-Cert -i example | pyndnsec Import-Cert
    //
    // The generated certificate's KeyLocator is trust anchor's CERTIFICATE name.

    // Sign Data packet with default identity
    auto default_cert = m_keyChain.getPib().getDefaultIdentity().getDefaultKey().getDefaultCertificate();
    m_keyChain.sign(*data, signingByCertificate(default_cert));

    // Return Data packet to the requester
    std::cout << "<< D: " << *data << std::endl;
    m_face.put(*data);
  }

  void
  onRegisterFailed(const Name& prefix, const std::string& reason)
  {
    std::cerr << "ERROR: Failed to register prefix '" << prefix
              << "' with the local forwarder (" << reason << ")" << std::endl;
    m_face.shutdown();
  }

private:
  Face m_face;
  KeyChain m_keyChain;
  ScopedRegisteredPrefixHandle m_certServeHandle;
};

} // namespace examples
} // namespace ndn

int
main(int argc, char** argv)
{
  try {
    ndn::examples::Producer producer;
    producer.run();
    return 0;
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
}