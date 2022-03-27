#include "lvs-validator.hpp"
#include "ndn-cxx/face.hpp"
#include "ndn-cxx/util/logger.hpp"
#include "ndn-cxx/security/verification-helpers.hpp"


namespace lvs {

using tlv::bstring_view;
using namespace std;
using namespace ndn;

NDN_LOG_INIT(lvs.Validator);

Validator::Validator(const bstring_view& binary_lvs,
                     ndn::Face& face,
                     const ndn::security::Certificate& trust_anchor):
  m_binary_lvs(binary_lvs.begin(), binary_lvs.end()),
  m_checker(nullptr), m_face(face), m_anchor(trust_anchor)
{
  auto model = lvs::LvsModel::Parse(bstring_view(m_binary_lvs.data(), m_binary_lvs.size()));
  if(!model.has_value()) {
    throw lvs::LvsModelError("Failed to parse LVS trust schema");
  }
  m_checker = std::unique_ptr<lvs::Checker>(new lvs::Checker(*model, {}));
}

void
Validator::validate(const ndn::Data& data,
                    const ndn::security::DataValidationSuccessCallback& successCb,
                    const ndn::security::DataValidationFailureCallback& failureCb)
{
  // Check name
  auto keyLocator = data.getKeyLocator();
  if(!keyLocator.has_value()){
    return failureCb(data, ndn::security::ValidationError::Code::NO_SIGNATURE);
  }
  if(!m_checker->check(data.getName(), keyLocator->getName())){
    NDN_LOG_INFO("LVS check failed: " << data.getName() << " does not match " << keyLocator->getName());
    return failureCb(data, ndn::security::ValidationError::Code::POLICY_ERROR);
  }

  // If trust anchor
  if(keyLocator->getName() == m_anchor.getName()){
    if(ndn::security::verifySignature(data, m_anchor)){
      return successCb(data);
    }else{
      return failureCb(data, ndn::security::ValidationError::Code::INVALID_SIGNATURE);
    }
  } else {
    // Fetch certificate
    ndn::Interest interest(keyLocator->getName());
    interest.setMustBeFresh(true);
    interest.setCanBePrefix(true);

    m_face.expressInterest(interest,
      [=, this](const Interest&, const Data& certData){
        validate(certData,
        [=](const Data& certDataVerified){
          ndn::security::Certificate cert;
          try{
            cert = ndn::security::Certificate(certDataVerified);
          }catch(ndn::tlv::Error&){
            return failureCb(data, ndn::security::ValidationError::Code::MALFORMED_CERT);
          }
          if(ndn::security::verifySignature(data, cert)){
            return successCb(data);
          }else{
            return failureCb(data, ndn::security::ValidationError::Code::INVALID_SIGNATURE);
          }
        },
        [=](const Data&, ndn::security::ValidationError){
          failureCb(data, ndn::security::ValidationError::Code::MALFORMED_CERT);
        });
      },
      [=](const Interest&, const lp::Nack& nack){
        failureCb(data, ndn::security::ValidationError::Code::CANNOT_RETRIEVE_CERT);
      },
      [=](const Interest&){
        failureCb(data, ndn::security::ValidationError::Code::CANNOT_RETRIEVE_CERT);
      }
    );
  }
}

} // namespace lvs