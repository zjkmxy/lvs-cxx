#include "lvs-validator.hpp"
#include "ndn-cxx/face.hpp"
#include "ndn-cxx/util/logger.hpp"
#include "ndn-cxx/security/verification-helpers.hpp"


namespace lvs {

using namespace std;
using namespace ndn;

NDN_LOG_INIT(lvs.Validator);

Validator::Validator(std::unique_ptr<Checker> checker,
                     ndn::Face& face,
                     const ndn::security::Certificate& trust_anchor):
  m_checker(std::move(checker)), m_face(face), m_anchor(trust_anchor)
{}

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
    NDN_LOG_ERROR(data.getName() << " does not match " << keyLocator->getName());
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
    interest.setCanBePrefix(false);

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