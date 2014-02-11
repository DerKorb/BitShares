#include <fc/filesystem.hpp>
#include <fc/exception/exception.hpp>
#include <fc/io/datastream.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/operations.hpp>
#include <fc/crypto/aes.hpp>
#include <bts/pts_address.hpp>

extern "C"
{
    #include "crypto_scrypt.h"
}

#include "multibit.pb.h"
#include <iostream>

namespace bts
{
      std::vector<fc::ecc::private_key> import_multibit_wallet( const fc::path& wallet_dat, const std::string& passphrase )
      {
          if (!fc::exists(wallet_dat))
              return std::vector<fc::ecc::private_key>();

          boost::filesystem::ifstream isWallet(wallet_dat);

          wallet::Wallet pbWallet;
          pbWallet.ParseFromIstream(&isWallet);

          std::string salt;
          if (pbWallet.encryption_type() == pbWallet.ENCRYPTED_SCRYPT_AES)
              salt = pbWallet.encryption_parameters().salt();

          std::vector<fc::ecc::private_key> keyReturn;
          for (int i = 0; i < pbWallet.key_size(); i++)
          {
              std::string pkeyData;

              std::cout << "key #" << i << std::endl;
              if (pbWallet.encryption_type() == pbWallet.UNENCRYPTED)
                  pkeyData = pbWallet.key(i).private_key();

              else if (pbWallet.encryption_type() == pbWallet.ENCRYPTED_SCRYPT_AES)
              {
                  std::cout << "  encrypted\n";
                  pkeyData = pbWallet.key(i).encrypted_private_key().encrypted_private_key();
                  std::string iv = pbWallet.key(i).encrypted_private_key().initialisation_vector();

                  // todo: get AES key from salt and password (scrypt)
                  unsigned char scryptKey[48];
                  int ret = crypto_scrypt((uint8_t*)passphrase.c_str(), passphrase.size(),
                                          (uint8_t*)salt.c_str(), salt.size(),
                                          pbWallet.encryption_parameters().n(),
                                          pbWallet.encryption_parameters().r(),
                                          pbWallet.encryption_parameters().p(),

                                          scryptKey, 48);
                  std::cout << "  kdf result: " << ret << "\n";
                  if (ret != 0)
                  {
                      // todo error handling
                      continue;
                  }

                  try
                  {
                      unsigned char output[48];
                      int klen = fc::aes_decrypt((unsigned char*)pkeyData.c_str(), pkeyData.size(), scryptKey, (unsigned char*)iv.c_str(), output);
                      if (!klen)
                      {
                          // todo decryption error
                          continue;
                      }

                      std::cout << "  decrypted key length: " << klen << "\n";
                      pkeyData.assign((char*)output, klen);
                  }
                  catch (fc::exception e)
                  {
                      std::cout << "something went wrong!\n" << e.to_string() << "\n" << e.to_detail_string() << "\n";
                  }
              }

              else
                  continue;

              fc::datastream<const char*> stream(pkeyData.c_str(), pkeyData.size());
              fc::sha256 bits;
              stream >> bits;

              keyReturn.push_back(fc::ecc::private_key::regenerate(bits));
          }

          return keyReturn;
      }
}
