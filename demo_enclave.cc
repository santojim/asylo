/*
 *
 * Copyright 2018 Asylo authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <string>
#include <vector>

#include "absl/base/macros.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "asylo/crypto/aead_cryptor.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/trusted_application.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "quickstart/demo.pb.h"
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <iostream>
#include <fstream>
#include <openssl/md5.h>
#include "openssl/sha.h"





namespace asylo {
namespace {

// Dummy 128-bit AES key.
constexpr uint8_t kAesKey128[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                  0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
                                  0x12, 0x13, 0x14, 0x15};
inline bool file_exists (const std::string& name) {
  struct stat buffer;
  return (stat (name.c_str(), &buffer) == 0);
}


std::string Md5Sum(std::string input) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    char string[] = "";

    strcpy( string, input.c_str() );
    MD5((unsigned char*)&string, strlen(string), (unsigned char*)&digest);

    char mdString[33];

    for(int i = 0; i < 16; i++)
         sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
    std::string md_string = std::string(mdString);
    return md_string;

}

std::string Sha1Sum(std::string input) {

    unsigned char digest[SHA_DIGEST_LENGTH];

    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx,(const char *) input.c_str(), strlen(input.c_str()));
    SHA1_Final(digest, &ctx);

    char mdString[SHA_DIGEST_LENGTH*2+1];
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

    std::string sha_string = std::string(mdString);
    return sha_string;

}

std::string Sha2Sum(std::string input) {
    unsigned char digest[SHA512_DIGEST_LENGTH];

    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx,(const char *) input.c_str(), strlen(input.c_str()));
    SHA512_Final(digest, &ctx);

    char mdString[SHA512_DIGEST_LENGTH*2+1];
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
        sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

    std::string sha512_string = std::string(mdString);
    return sha512_string;
//    printf("SHA512 digest: %s\n", mdString);

}

bool generate_key() {
        size_t pri_len;            // Length of private key
        size_t pub_len;            // Length of public key
        char *pri_key;           // Private key in PEM
        char *pub_key;           // Public key in PEM

        int ret = 0;
        RSA *r = NULL;
        BIGNUM *bne = NULL;
        BIO *bp_public = NULL, *bp_private = NULL;
        int bits = 2048;
        unsigned long e = RSA_F4;

        RSA *pb_rsa = NULL;
        RSA *p_rsa = NULL;
        EVP_PKEY *evp_pbkey = NULL;
        EVP_PKEY *evp_pkey = NULL;

        BIO *pbkeybio = NULL;
        BIO *pkeybio = NULL;
        FILE *pkey_file = fopen("private.pem", "wb");
        FILE *pbkey_file = fopen("public.pem", "wb");
        FILE *pbkey_from_file = fopen("public.pem","r");
        FILE *pkey_from_file = fopen("private.pem","r");
        // 0. check if key already exits
        if (file_exists("private.pem") ) {
            std::cout<< "private pem exists" <<std::endl;
        }
        else {
            std::cout<<"private.pem doesn't exist " << std::endl;
        }
        // 1. generate rsa key
        bne = BN_new();
        ret = BN_set_word(bne, e);
        if (ret != 1) {
            goto free_all;
        }

        r = RSA_new();
        ret = RSA_generate_key_ex(r, bits, bne, NULL);
        if (ret != 1) {
            goto free_all;
        }

        // 2. save public key in file private.pem
        // ----------------------private key to file-------------------------//
        if (!pkey_file) {
            std::cerr << "Unable to open \"private.pem\" for writing." << std::endl;
            return false;
        }
        ret = PEM_write_RSAPrivateKey(pkey_file, r, NULL, NULL, 0, NULL, NULL);
        fclose(pkey_file);
        if(!ret) {
            std::cerr << "Unable to write private key to disk." << std::endl;
            return false;
        }
        // ----------------------public key to file-------------------------//
        if (!pbkey_file) {
            std::cerr << "Unable to open \"public.pem\" for writing." << std::endl;
            return false;
        }
        ret = PEM_write_RSAPublicKey(pbkey_file, r);
        fclose(pbkey_file);
        if(!ret) {
            std::cerr << "Unable to write public key to disk." << std::endl;
            return false;
        }
        // -----------------------------------------------------------------//
        //bp_public = BIO_new_file("public.pem", "w");
        bp_public = BIO_new(BIO_s_mem());
        ret = PEM_write_bio_RSAPublicKey(bp_public, r);
        if (ret != 1) {
            goto free_all;
        }

        // 3. save private key
        //bp_private = BIO_new_file("private.pem", "w");
        bp_private = BIO_new(BIO_s_mem());
        ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
        if (ret != 1) {
            goto free_all;
        }

        //4. Get the keys are PEM formatted strings

        pri_len = BIO_pending(bp_private);
        pub_len = BIO_pending(bp_public);

        pri_key = (char*) malloc(pri_len + 1);
        pub_key = (char*) malloc(pub_len + 1);

        BIO_read(bp_private, pri_key, pri_len);
        BIO_read(bp_public, pub_key, pub_len);

        pri_key[pri_len] = '\0';
        pub_key[pub_len] = '\0';

        printf("\n%s\n%s\n", pri_key, pub_key);

        //verify if you are able to re-construct the keys
        pbkeybio = BIO_new_mem_buf((void*) pub_key, pub_len);
        if (pbkeybio == NULL) {
            return -1;
        }
        pb_rsa = PEM_read_bio_RSAPublicKey(pbkeybio, &pb_rsa, NULL, NULL);
        if (pb_rsa == NULL) {
            char buffer[120];
            ERR_error_string(ERR_get_error(), buffer);
            printf("Error reading public key:%s\n", buffer);
        }
        evp_pbkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(evp_pbkey, pb_rsa);

        pkeybio = BIO_new_mem_buf((void*) pri_key, pri_len);
        BIO_read_filename (pkeybio, "private.pem");
        if (pkeybio == NULL) {
            return -1;
        }
        p_rsa = PEM_read_bio_RSAPrivateKey(pkeybio, &p_rsa, NULL, NULL);
        if (p_rsa == NULL) {
            char buffer[120];
            ERR_error_string(ERR_get_error(), buffer);
            printf("Error reading private key:%s\n", buffer);
        }
        evp_pkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(evp_pkey, p_rsa);

        BIO_free(pbkeybio);
        BIO_free(pkeybio);
        // 5. read from file
        p_rsa = PEM_read_RSAPublicKey(pbkey_from_file,&p_rsa,NULL,NULL);
        std::cout << "from file key n=:" << p_rsa->n << std::endl;
        std::cout << "from file key e=:" << p_rsa->e << std::endl;
        std::cout << "from file key d=:" << p_rsa->d << std::endl;
        std::cout << "from file key dmp1=:" << p_rsa->dmp1 << std::endl;
        std::cout << "from file key dmq1=:" << p_rsa->dmq1 << std::endl;
        p_rsa = PEM_read_RSAPrivateKey(pkey_from_file,&p_rsa,NULL,NULL);
        std::cout << "from file key n=:" << p_rsa->n << std::endl;
        std::cout << "from file key e=:" << p_rsa->e << std::endl;
        std::cout << "from file key d=:" << p_rsa->d << std::endl;
        std::cout << "from file key dmp1=:" << p_rsa->dmp1 << std::endl;
        std::cout << "from file key dmq1:" << p_rsa->dmq1 << std::endl;

        // 4. free
        free_all:

        BIO_free_all(bp_public);
        BIO_free_all(bp_private);
        RSA_free(r);
        BN_free(bne);

        return (ret == 1);
    }


// Helper function that adapts absl::BytesToHexString, allowing it to be used
// with ByteContainerView.
std::string BytesToHexString(ByteContainerView bytes) {
  return absl::BytesToHexString(absl::string_view(
      reinterpret_cast<const char *>(bytes.data()), bytes.size()));
}

// Encrypts a message against `kAesKey128` and returns a 12-byte nonce followed
// by authenticated ciphertext, encoded as a hex string.
const StatusOr<std::string> EncryptMessage(const std::string &message) {
  std::unique_ptr<AeadCryptor> cryptor;
  ASYLO_ASSIGN_OR_RETURN(cryptor,
                         AeadCryptor::CreateAesGcmSivCryptor(kAesKey128));

  std::vector<uint8_t> additional_authenticated_data;
  std::vector<uint8_t> nonce(cryptor->NonceSize());
  std::vector<uint8_t> ciphertext(message.size() + cryptor->MaxSealOverhead());
  size_t ciphertext_size;

  ASYLO_RETURN_IF_ERROR(cryptor->Seal(
      message, additional_authenticated_data, absl::MakeSpan(nonce),
      absl::MakeSpan(ciphertext), &ciphertext_size));

  return absl::StrCat(BytesToHexString(nonce), BytesToHexString(ciphertext));
}

// Decrypts a message using `kAesKey128`. Expects `nonce_and_ciphertext` to be
// encoded as a hex string, and lead with a 12-byte nonce. Intended to be
// used by the reader for completing the exercise.
const StatusOr<CleansingString> DecryptMessage(
    const std::string &nonce_and_ciphertext) {
  std::string input_bytes = absl::HexStringToBytes(nonce_and_ciphertext);

  std::unique_ptr<AeadCryptor> cryptor;
  ASYLO_ASSIGN_OR_RETURN(cryptor,
                         AeadCryptor::CreateAesGcmSivCryptor(kAesKey128));

  if (input_bytes.size() < cryptor->NonceSize()) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        absl::StrCat("Input too short: expected at least ",
                     cryptor->NonceSize(), " bytes, got ", input_bytes.size()));
  }

  std::vector<uint8_t> additional_authenticated_data;
  std::vector<uint8_t> nonce = {input_bytes.begin(),
                                input_bytes.begin() + cryptor->NonceSize()};
  std::vector<uint8_t> ciphertext = {input_bytes.begin() + cryptor->NonceSize(),
                                     input_bytes.end()};

  // The plaintext is always smaller than the ciphertext, so use
  // `ciphertext.size()` as an upper bound on the plaintext buffer size.
  CleansingVector<uint8_t> plaintext(ciphertext.size());
  size_t plaintext_size;

  ASYLO_RETURN_IF_ERROR(cryptor->Open(ciphertext, additional_authenticated_data,
                                      nonce, absl::MakeSpan(plaintext),
                                      &plaintext_size));

  return CleansingString(plaintext.begin(), plaintext.end());
}

}  // namespace

class EnclaveDemo : public TrustedApplication {
 public:
  EnclaveDemo() = default;

//  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
//    std::string user_message = GetEnclaveUserMessage(input);
//
//    std::string result;
//    ASYLO_ASSIGN_OR_RETURN(result, EncryptMessage(user_message));
//    SetEnclaveOutputMessage(output,result);
//    SetEnclaveOutputMessage(output,Md5Sum(user_message));
//    SetEnclaveOutputMessage(output,Sha1Sum(user_message));
//    SetEnclaveOutputMessage(output,Sha2Sum(user_message));
//    std::cout << "eclave side :Encrypted message:" << std::endl << result << std::endl;
////    generate_key();
////    std::cout<<"md5sum returned: " << Md5Sum(user_message) << std::endl;
////    std::cout<<"sha returned: " << Sha1Sum(user_message) << std::endl;
////    std::cout<<"sha512 returned: " << Sha2Sum(user_message) << std::endl;
//
//    return Status::OkStatus();
//  }
  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    std::string user_message = GetEnclaveUserMessage(input);

    switch (GetEnclaveUserAction(input)) {
      case guide::asylo::Demo::ENCRYPT: {
        std::string result;
        ASYLO_ASSIGN_OR_RETURN(result, EncryptMessage(user_message));
        SetEnclaveOutputMessage(output, result);
        break;
      }
      case guide::asylo::Demo::MD5SUM: {
        SetEnclaveOutputMessage(output, Md5Sum(user_message));
        break;
      }
      case guide::asylo::Demo::SHA1SUM: {
        SetEnclaveOutputMessage(output, Sha1Sum(user_message));
        break;
      }
      case guide::asylo::Demo::SHA512SUM: {
        SetEnclaveOutputMessage(output, Sha2Sum(user_message));
        break;
      }
      case guide::asylo::Demo::DECRYPT: {
        CleansingString result;
        ASYLO_ASSIGN_OR_RETURN(result, DecryptMessage(user_message));
        SetEnclaveOutputMessage(output, result);
        break;
      }
      default:
        return Status(error::GoogleError::INVALID_ARGUMENT,
                      "Action unspecified");
    }

    return Status::OkStatus();
  }

  // Retrieves user message from |input|.
  const std::string GetEnclaveUserMessage(const EnclaveInput &input) {
    return input.GetExtension(guide::asylo::quickstart_input).value();
  }
  // Retrieves user action from |input|.
  guide::asylo::Demo::Action GetEnclaveUserAction(const EnclaveInput &input) {
    return input.GetExtension(guide::asylo::quickstart_input).action();
  }
  // Populates |enclave_output|->value() with |output_message|. Intended to be
  // used by the reader for completing the exercise.
  void SetEnclaveOutputMessage(EnclaveOutput *enclave_output,
                               absl::string_view output_message) {
    guide::asylo::Demo *output =
        enclave_output->MutableExtension(guide::asylo::quickstart_output);
    output->set_value(std::string(output_message));
  }
};

//  // Populates |enclave_output|->value() with |output_message|. Intended to be
//  // used by the reader for completing the exercise.
//  void SetEnclaveOutputMessage(EnclaveOutput *enclave_output,
//                               const std::string &output_message) {
//    guide::asylo::Demo *output =
//        enclave_output->MutableExtension(guide::asylo::quickstart_output);
//    output->set_value(output_message);
//  }
//};

TrustedApplication *BuildTrustedApplication() { return new EnclaveDemo; }

}  // namespace asylo
