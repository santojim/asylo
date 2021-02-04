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

#include <iostream>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "asylo/client.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/util/logging.h"
#include "quickstart/demo.pb.h"

//ABSL_FLAG(std::string, enclave_path, "",
//          "Path to enclave binary image to load");
//ABSL_FLAG(std::string, message, "", "Message to encrypt");
ABSL_FLAG(std::string, enclave_path, "", "Path to enclave to load");
ABSL_FLAG(std::string, message1, "", "The first message to encrypt");
ABSL_FLAG(std::string, md5sum, "", "The message to digest using md5sum");
ABSL_FLAG(std::string, sha1sum, "", "The message to digest using sha1sum");
ABSL_FLAG(std::string, sha512sum, "", "The message to digest using sha512sum");
ABSL_FLAG(std::string, message2, "", "The second message to encrypt");
ABSL_FLAG(std::string, ciphertext, "", "The ciphertext message to decrypt");

// Populates |enclave_input|->value() with |user_message|.
//void SetEnclaveUserMessage(asylo::EnclaveInput *enclave_input,
//                           const std::string &user_message) {
//  guide::asylo::Demo *user_input =
//      enclave_input->MutableExtension(guide::asylo::quickstart_input);
//  user_input->set_value(user_message);
//}
void SetEnclaveUserMessage(asylo::EnclaveInput *enclave_input,
                           const std::string &user_message,
                           guide::asylo::Demo::Action action) {
  guide::asylo::Demo *user_input =
      enclave_input->MutableExtension(guide::asylo::quickstart_input);
  user_input->set_value(user_message);
  user_input->set_action(action);
}

// Retrieves encrypted message from |output|. Intended to be used by the reader
// for completing the exercise.
const std::string GetEnclaveOutputMessage(const asylo::EnclaveOutput &output) {
  return output.GetExtension(guide::asylo::quickstart_output).value();
}

int main(int argc, char *argv[]) {
  absl::ParseCommandLine(argc, argv);

  constexpr char kEnclaveName[] = "demo_enclave";

//  const std::string message = absl::GetFlag(FLAGS_message);
//  LOG_IF(QFATAL, message.empty()) << "Empty --message flag.";
//
  const std::string enclave_path = absl::GetFlag(FLAGS_enclave_path);
//  LOG_IF(QFATAL, enclave_path.empty()) << "Empty --enclave_path flag.";
//
  LOG_IF(QFATAL, absl::GetFlag(FLAGS_message1).empty() &&
                     absl::GetFlag(FLAGS_message2).empty() &&
                     absl::GetFlag(FLAGS_ciphertext).empty())
      << "Must specify at least one of --message1, --message2, or --ciphertext "
         "flag values";

  // Part 1: Initialization

  // Prepare |EnclaveManager| with default |EnclaveManagerOptions|
  asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
  auto manager_result = asylo::EnclaveManager::Instance();
  LOG_IF(QFATAL, !manager_result.ok()) << "Could not obtain EnclaveManager";

  // Prepare |load_config| message.
  asylo::EnclaveLoadConfig load_config;
  load_config.set_name(kEnclaveName);

  // Prepare |sgx_config| message.
  auto sgx_config = load_config.MutableExtension(asylo::sgx_load_config);
  sgx_config->set_debug(true);
  auto file_enclave_config = sgx_config->mutable_file_enclave_config();
  file_enclave_config->set_enclave_path(enclave_path);

  // Load Enclave with prepared |EnclaveManager| and |load_config| message.
  asylo::EnclaveManager *manager = manager_result.ValueOrDie();
  auto status = manager->LoadEnclave(load_config);
  LOG_IF(QFATAL, !status.ok()) << "LoadEnclave failed with: " << status;

  // Part 2: Secure execution

  // Prepare |input| with |message| and create |output| to retrieve response
  // from enclave.
  asylo::EnclaveInput input;
  asylo::EnclaveOutput output;

  // Get |EnclaveClient| for loaded enclave and execute |EnterAndRun|.
  asylo::EnclaveClient *const client = manager->GetClient(kEnclaveName);
  status = client->EnterAndRun(input, &output);

  if (!absl::GetFlag(FLAGS_message1).empty()) {
    SetEnclaveUserMessage(&input, absl::GetFlag(FLAGS_message1),
                          guide::asylo::Demo::ENCRYPT);
    status = client->EnterAndRun(input, &output);
    LOG_IF(QFATAL, !status.ok()) << "EnterAndRun failed with: " << status;
    std::cout << "Encrypted message1 from driver:" << std::endl
              << GetEnclaveOutputMessage(output) << std::endl;
  }

  if (!absl::GetFlag(FLAGS_md5sum).empty()) {
    SetEnclaveUserMessage(&input, absl::GetFlag(FLAGS_md5sum),
                          guide::asylo::Demo::MD5SUM);
    status = client->EnterAndRun(input, &output);
    LOG_IF(QFATAL, !status.ok()) << "EnterAndRun failed with: " << status;
    std::cout << "Digest md5sum from driver:" << std::endl
              << GetEnclaveOutputMessage(output) << std::endl;
  }

  if (!absl::GetFlag(FLAGS_sha1sum).empty()) {
    SetEnclaveUserMessage(&input, absl::GetFlag(FLAGS_sha1sum),
                          guide::asylo::Demo::SHA1SUM);
    status = client->EnterAndRun(input, &output);
    LOG_IF(QFATAL, !status.ok()) << "EnterAndRun failed with: " << status;
    std::cout << "Digest sha1 from driver:" << std::endl
              << GetEnclaveOutputMessage(output) << std::endl;
  }

  if (!absl::GetFlag(FLAGS_sha512sum).empty()) {
    SetEnclaveUserMessage(&input, absl::GetFlag(FLAGS_sha512sum),
                          guide::asylo::Demo::SHA512SUM);
    status = client->EnterAndRun(input, &output);
    LOG_IF(QFATAL, !status.ok()) << "EnterAndRun failed with: " << status;
    std::cout << "Digest sha512 from driver:" << std::endl
              << GetEnclaveOutputMessage(output) << std::endl;
  }

  if (!absl::GetFlag(FLAGS_message2).empty()) {
    SetEnclaveUserMessage(&input, absl::GetFlag(FLAGS_message2),
                          guide::asylo::Demo::ENCRYPT);
    status = client->EnterAndRun(input, &output);
    LOG_IF(QFATAL, !status.ok()) << "EnterAndRun failed with: " << status;
    std::cout << "Encrypted message2 from driver:" << std::endl
              << GetEnclaveOutputMessage(output) << std::endl;
  }

  if (!absl::GetFlag(FLAGS_ciphertext).empty()) {
    SetEnclaveUserMessage(&input, absl::GetFlag(FLAGS_ciphertext),
                          guide::asylo::Demo::DECRYPT);
    status = client->EnterAndRun(input, &output);
    LOG_IF(QFATAL, !status.ok()) << "EnterAndRun failed with: " << status;
    std::cout << "Decrypted ciphertext from driver:" << std::endl
              << GetEnclaveOutputMessage(output) << std::endl;
  }
//  LOG_IF(QFATAL, !status.ok()) << "EnterAndRun failed with: " << status;
//  std::cout << "Encrypted message from driver:" << std::endl
//                  << GetEnclaveOutputMessage(output) << std::endl;
//  status = client->EnterAndRun(input2, &output);
//  LOG_IF(QFATAL, !status.ok()) << "EnterAndRun failed with: " << status;
//  std::cout << "Encrypted message2 from driver:" << std::endl
//                  << GetEnclaveOutputMessage(output) << std::endl;
//
  // Part 3: Finalization

  // |DestroyEnclave| before exiting program.
  asylo::EnclaveFinal empty_final_input;
  status = manager->DestroyEnclave(client, empty_final_input);
  LOG_IF(QFATAL, !status.ok()) << "DestroyEnclave failed with: " << status;

  return 0;
}