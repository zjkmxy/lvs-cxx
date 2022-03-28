#include "lvs-validator.hpp"
#include "ndn-cxx/face.hpp"
#include "ndn-cxx/util/logger.hpp"
#include "ndn-cxx/security/verification-helpers.hpp"


namespace lvs {

using tlv::bstring_view;
using namespace std;

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
  auto keyLocator = data.getKeyLocator();
  if(!keyLocator.has_value()){
    return failureCb(data, ndn::security::ValidationError::Code::NO_SIGNATURE);
  }

  // If trust anchor
  if(keyLocator->getName().isPrefixOf(m_anchor.getName())){
    if(!ndn::security::verifySignature(data, m_anchor)){
      return failureCb(data, ndn::security::ValidationError::Code::INVALID_SIGNATURE);
    }
    // Check name
    if(!m_checker->check(data.getName(), m_anchor.getName())){
      NDN_LOG_INFO("LVS check failed: " << data.getName() << " does not match " << m_anchor.getName());
      return failureCb(data, ndn::security::ValidationError::Code::POLICY_ERROR);
    }
    return successCb(data);
  } else {
    // Fetch certificate
    ndn::Interest interest(keyLocator->getName());
    interest.setMustBeFresh(true);
    interest.setCanBePrefix(true);

    m_face.expressInterest(interest,
      [failureCb, successCb, data, this](const ndn::Interest&, const ndn::Data& certData){
        validate(certData,
        [=](const ndn::Data& certDataVerified){
          ndn::security::Certificate cert;
          try{
            cert = ndn::security::Certificate(certDataVerified);
          }catch(ndn::tlv::Error&){
            return failureCb(data, ndn::security::ValidationError::Code::MALFORMED_CERT);
          }
          if(!ndn::security::verifySignature(data, cert)){
            return failureCb(data, ndn::security::ValidationError::Code::INVALID_SIGNATURE);
          }
          // Check name
          if(!m_checker->check(data.getName(), cert.getName())){
            NDN_LOG_INFO("LVS check failed: " << data.getName() << " does not match " << cert.getName());
            return failureCb(data, ndn::security::ValidationError::Code::POLICY_ERROR);
          }
          return successCb(data);
        },
        [failureCb, data](const ndn::Data&, ndn::security::ValidationError){
          failureCb(data, ndn::security::ValidationError::Code::MALFORMED_CERT);
        });
      },
      [failureCb, data](const ndn::Interest&, const ndn::lp::Nack& nack){
        failureCb(data, ndn::security::ValidationError::Code::CANNOT_RETRIEVE_CERT);
      },
      [failureCb, data](const ndn::Interest&){
        failureCb(data, ndn::security::ValidationError::Code::CANNOT_RETRIEVE_CERT);
      }
    );
  }
}

} // namespace lvs