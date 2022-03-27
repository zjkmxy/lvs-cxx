#pragma once

#include <memory>
#include "ndn-cxx/face.hpp"
#include "ndn-cxx/security/certificate-storage.hpp"
#include "ndn-cxx/security/validation-callback.hpp"
#include "lvs-checker.hpp"

namespace lvs {

class Validator: public ndn::security::CertificateStorage {
public:
  Validator(std::unique_ptr<Checker> checker,
            ndn::Face& face,
            const ndn::security::Certificate& trust_anchor);

  ~Validator() = default;

  void
  validate(const ndn::Data& data,
           const ndn::security::DataValidationSuccessCallback& successCb,
           const ndn::security::DataValidationFailureCallback& failureCb);

private:
  std::unique_ptr<Checker> m_checker;
  ndn::Face& m_face;
  ndn::security::Certificate m_anchor;
};

} // namespace lvs
