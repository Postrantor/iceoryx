// Copyright (c) 2019, 2021 by Robert Bosch GmbH. All rights reserved.
// Copyright (c) 2020 - 2022 by Apex.AI Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#include "iceoryx_posh/internal/runtime/ipc_interface_base.hpp"
#include "iceoryx_dust/cxx/convert.hpp"
#include "iceoryx_posh/internal/runtime/ipc_message.hpp"
#include "iox/logging.hpp"

#include <thread>

namespace iox
{
namespace runtime
{
/**
 * @brief 将字符串转换为 IpcMessageType 枚举类型 (Converts a string to an IpcMessageType enumeration)
 * @param[in] str 输入的字符串 (The input string)
 * @return 转换后的 IpcMessageType 枚举类型，如果失败则返回 IpcMessageType::NOTYPE (The converted IpcMessageType enumeration, or IpcMessageType::NOTYPE if the conversion fails)
 */
IpcMessageType stringToIpcMessageType(const char * str) noexcept
{
  // 定义 msg 变量，类型为 IpcMessageType 的底层类型 (Define the variable msg with the underlying type of IpcMessageType)
  std::underlying_type<IpcMessageType>::type msg;

  // 检查输入字符串是否为整数 (Check if the input string is an integer)
  bool noError = cxx::convert::stringIsNumber(str, cxx::convert::NumberType::INTEGER);

  // 如果是整数，则尝试将字符串转换为 msg 类型 (If it's an integer, try converting the string to the msg type)
  noError &= noError ? (cxx::convert::fromString(str, msg)) : false;

  // 检查 msg 是否在 IpcMessageType::BEGIN 和 IpcMessageType::END 之间 (Check if msg is between IpcMessageType::BEGIN and IpcMessageType::END)
  noError &=
    noError
      ? !(static_cast<std::underlying_type<IpcMessageType>::type>(IpcMessageType::BEGIN) >= msg ||
          static_cast<std::underlying_type<IpcMessageType>::type>(IpcMessageType::END) <= msg)
      : false;

  // 如果没有错误，则返回对应的 IpcMessageType，否则返回 IpcMessageType::NOTYPE (Return the corresponding IpcMessageType if there are no errors, otherwise return IpcMessageType::NOTYPE)
  return noError ? (static_cast<IpcMessageType>(msg)) : IpcMessageType::NOTYPE;
}

/**
 * @brief 将 IpcMessageType 枚举类型转换为字符串 (Converts an IpcMessageType enumeration to a string)
 * @param[in] msg 输入的 IpcMessageType 枚举类型 (The input IpcMessageType enumeration)
 * @return 转换后的字符串 (The converted string)
 */
std::string IpcMessageTypeToString(const IpcMessageType msg) noexcept
{
  // 使用底层类型将 IpcMessageType 转换为字符串 (Convert the IpcMessageType to a string using its underlying type)
  return cxx::convert::toString(static_cast<std::underlying_type<IpcMessageType>::type>(msg));
}

/**
 * @brief 将字符串转换为 IpcMessageErrorType 枚举类型 (Converts a string to an IpcMessageErrorType enumeration)
 * @param[in] str 输入的字符串 (The input string)
 * @return 转换后的 IpcMessageErrorType 枚举类型，如果失败则返回 IpcMessageErrorType::NOTYPE (The converted IpcMessageErrorType enumeration, or IpcMessageErrorType::NOTYPE if the conversion fails)
 */
IpcMessageErrorType stringToIpcMessageErrorType(const char * str) noexcept
{
  // 定义 msg 变量，类型为 IpcMessageErrorType 的底层类型 (Define the variable msg with the underlying type of IpcMessageErrorType)
  std::underlying_type<IpcMessageErrorType>::type msg;

  // 检查输入字符串是否为整数 (Check if the input string is an integer)
  bool noError = cxx::convert::stringIsNumber(str, cxx::convert::NumberType::INTEGER);

  // 如果是整数，则尝试将字符串转换为 msg 类型 (If it's an integer, try converting the string to the msg type)
  noError &= noError ? (cxx::convert::fromString(str, msg)) : false;

  // 检查 msg 是否在 IpcMessageErrorType::BEGIN 和 IpcMessageErrorType::END 之间 (Check if msg is between IpcMessageErrorType::BEGIN and IpcMessageErrorType::END)
  noError &= noError ? !(static_cast<std::underlying_type<IpcMessageErrorType>::type>(
                           IpcMessageErrorType::BEGIN) >= msg ||
                         static_cast<std::underlying_type<IpcMessageErrorType>::type>(
                           IpcMessageErrorType::END) <= msg)
                     : false;

  // 如果没有错误，则返回对应的 IpcMessageErrorType，否则返回 IpcMessageErrorType::NOTYPE (Return the corresponding IpcMessageErrorType if there are no errors, otherwise return IpcMessageErrorType::NOTYPE)
  return noError ? (static_cast<IpcMessageErrorType>(msg)) : IpcMessageErrorType::NOTYPE;
}

/**
 * @brief 将 IpcMessageErrorType 枚举类型转换为字符串 (Converts an IpcMessageErrorType enumeration to a string)
 * @param[in] msg 输入的 IpcMessageErrorType 枚举类型 (The input IpcMessageErrorType enumeration)
 * @return 转换后的字符串 (The converted string)
 */
std::string IpcMessageErrorTypeToString(const IpcMessageErrorType msg) noexcept
{
  // 使用底层类型将 IpcMessageErrorType 转换为字符串 (Convert the IpcMessageErrorType to a string using its underlying type)
  return cxx::convert::toString(static_cast<std::underlying_type<IpcMessageErrorType>::type>(msg));
}

/**
 * @brief IpcInterface 构造函数 (IpcInterface constructor)
 * @tparam IpcChannelType 用于 IPC 通信的通道类型 (The channel type used for IPC communication)
 * @param[in] runtimeName 运行时名称 (Runtime name)
 * @param[in] maxMessages 最大消息数量 (Maximum number of messages)
 * @param[in] messageSize 消息大小 (Message size)
 */
template <typename IpcChannelType>
IpcInterface<IpcChannelType>::IpcInterface(
  const RuntimeName_t & runtimeName,
  const uint64_t maxMessages,
  const uint64_t messageSize) noexcept
: m_runtimeName(runtimeName) // 初始化运行时名称 (Initialize the runtime name)
{
  // 设置最大消息数量和消息大小 (Set the maximum number of messages and message size)
  m_maxMessages = maxMessages;
  m_maxMessageSize = messageSize;

  // 如果消息大小超过了允许的最大值，发出警告并减小消息大小 (If the message size exceeds the allowed maximum, issue a warning and reduce the message size)
  if (m_maxMessageSize > platform::IoxIpcChannelType::MAX_MESSAGE_SIZE) {
    IOX_LOG(WARN) << "Message size too large, reducing from " << messageSize << " to "
                  << platform::IoxIpcChannelType::MAX_MESSAGE_SIZE;
    m_maxMessageSize = platform::IoxIpcChannelType::MAX_MESSAGE_SIZE;
  }
}

/**
 * @brief 接收 IPC 消息 (Receive an IPC message)
 *
 * @tparam IpcChannelType 用于通信的 IPC 通道类型 (IPC channel type used for communication)
 * @param[out] answer 存储接收到的 IPC 消息 (Stores the received IPC message)
 * @return 成功接收返回 true，否则返回 false (Returns true if successful, otherwise returns false)
 */
template <typename IpcChannelType>
bool IpcInterface<IpcChannelType>::receive(IpcMessage & answer) const noexcept
{
  // 尝试从 IPC 通道接收消息 (Attempt to receive a message from the IPC channel)
  auto message = m_ipcChannel.receive();

  // 如果接收到的消息有错误，则返回 false (If the received message has an error, return false)
  if (message.has_error()) {
    return false;
  }

  // 将接收到的字符串消息转换为 IpcMessage 类型，并存储在 answer 中 (Convert the received string message into an IpcMessage type and store it in answer)
  return IpcInterface<IpcChannelType>::setMessageFromString(message.value().c_str(), answer);
}

/**
 * @brief 在给定超时时间内接收 IPC 消息 (Receive an IPC message within the given timeout duration)
 *
 * @tparam IpcChannelType 用于通信的 IPC 通道类型 (IPC channel type used for communication)
 * @param[in] timeout 超时时间 (Timeout duration)
 * @param[out] answer 存储接收到的 IPC 消息 (Stores the received IPC message)
 * @return 成功接收返回 true，否则返回 false (Returns true if successful, otherwise returns false)
 */
template <typename IpcChannelType>
bool IpcInterface<IpcChannelType>::timedReceive(
  const units::Duration timeout, IpcMessage & answer) const noexcept
{
  // 在给定的超时时间内尝试从 IPC 通道接收消息 (Attempt to receive a message from the IPC channel within the given timeout duration)
  return !m_ipcChannel.timedReceive(timeout)
            .and_then([&answer](auto & message) {
              // 将接收到的字符串消息转换为 IpcMessage 类型，并存储在 answer 中 (Convert the received string message into an IpcMessage type and store it in answer)
              IpcInterface<IpcChannelType>::setMessageFromString(message.c_str(), answer);
            })
            .has_error() &&
         answer.isValid();
}

/**
 * @brief 将字符串消息转换为 IpcMessage 类型 (Convert a string message into an IpcMessage type)
 *
 * @tparam IpcChannelType 用于通信的 IPC 通道类型 (IPC channel type used for communication)
 * @param[in] buffer 字符串消息 (String message)
 * @param[out] answer 存储转换后的 IpcMessage (Stores the converted IpcMessage)
 * @return 转换成功返回 true，否则返回 false (Returns true if successful, otherwise returns false)
 */
template <typename IpcChannelType>
bool IpcInterface<IpcChannelType>::setMessageFromString(
  const char * buffer, IpcMessage & answer) noexcept
{
  // 将字符串消息设置为 IpcMessage 类型 (Set the string message as an IpcMessage type)
  answer.setMessage(buffer);

  // 如果转换后的 IpcMessage 无效，则记录错误并返回 false (If the converted IpcMessage is invalid, log the error and return false)
  if (!answer.isValid()) {
    IOX_LOG(ERROR) << "The received message " << answer.getMessage() << " is not valid";
    return false;
  }

  // 转换成功，返回 true (Conversion successful, return true)
  return true;
}

/**
 * @brief 发送 IPC 消息 (Send an IPC message)
 *
 * @tparam IpcChannelType 用于发送和接收 IPC 消息的通道类型 (The channel type used for sending and receiving IPC messages)
 * @param msg 要发送的 IPC 消息 (The IPC message to be sent)
 * @return 如果消息成功发送，则返回 true，否则返回 false (Returns true if the message is successfully sent, otherwise returns false)
 */
template <typename IpcChannelType>
bool IpcInterface<IpcChannelType>::send(const IpcMessage & msg) const noexcept
{
  // 判断消息是否有效 (Check if the message is valid)
  if (!msg.isValid()) {
    // 输出错误日志 (Output error log)
    IOX_LOG(ERROR) << "Trying to send the message " << msg.getMessage() << " which "
                   << "does not follow the specified syntax.";
    return false;
  }

  // 定义一个 lambda 函数，用于处理消息长度错误 (Define a lambda function to handle message length errors)
  auto logLengthError = [&msg](posix::IpcChannelError & error) {
    if (error == posix::IpcChannelError::MESSAGE_TOO_LONG) {
      const uint64_t messageSize =
        msg.getMessage().size() + platform::IoxIpcChannelType::NULL_TERMINATOR_SIZE;
      IOX_LOG(ERROR) << "msg size of " << messageSize << " bigger than configured max message size";
    }
  };
  // 发送消息并检查是否有错误 (Send the message and check for errors)
  return !m_ipcChannel.send(msg.getMessage()).or_else(logLengthError).has_error();
}

/**
 * @brief 发送 IPC 消息，并在指定的超时时间内等待发送完成 (Send an IPC message and wait for it to be sent within the specified timeout)
 *
 * @tparam IpcChannelType 用于发送和接收 IPC 消息的通道类型 (The channel type used for sending and receiving IPC messages)
 * @param msg 要发送的 IPC 消息 (The IPC message to be sent)
 * @param timeout 发送超时时间 (The timeout for sending the message)
 * @return 如果消息成功发送，则返回 true，否则返回 false (Returns true if the message is successfully sent, otherwise returns false)
 */
template <typename IpcChannelType>
bool IpcInterface<IpcChannelType>::timedSend(
  const IpcMessage & msg, units::Duration timeout) const noexcept
{
  // 判断消息是否有效 (Check if the message is valid)
  if (!msg.isValid()) {
    // 输出错误日志 (Output error log)
    IOX_LOG(ERROR) << "Trying to send the message " << msg.getMessage() << " which "
                   << "does not follow the specified syntax.";
    return false;
  }

  // 定义一个 lambda 函数，用于处理消息长度错误 (Define a lambda function to handle message length errors)
  auto logLengthError = [&msg](posix::IpcChannelError & error) {
    if (error == posix::IpcChannelError::MESSAGE_TOO_LONG) {
      const uint64_t messageSize =
        msg.getMessage().size() + platform::IoxIpcChannelType::NULL_TERMINATOR_SIZE;
      IOX_LOG(ERROR) << "msg size of " << messageSize << " bigger than configured max message size";
    }
  };
  // 在指定的超时时间内发送消息并检查是否有错误 (Send the message within the specified timeout and check for errors)
  return !m_ipcChannel.timedSend(msg.getMessage(), timeout).or_else(logLengthError).has_error();
}

/**
 * @brief 获取运行时名称 (Get the runtime name)
 *
 * @tparam IpcChannelType IPC通道类型 (IPC channel type)
 * @return 运行时名称 (RuntimeName_t) (The runtime name (RuntimeName_t))
 */
template <typename IpcChannelType>
const RuntimeName_t & IpcInterface<IpcChannelType>::getRuntimeName() const noexcept
{
  // 返回m_runtimeName成员变量 (Return the m_runtimeName member variable)
  return m_runtimeName;
}

/**
 * @brief 判断IPC通道是否初始化 (Check if the IPC channel is initialized)
 *
 * @tparam IpcChannelType IPC通道类型 (IPC channel type)
 * @return 初始化状态 (bool) (Initialization status (bool))
 */
template <typename IpcChannelType> bool IpcInterface<IpcChannelType>::isInitialized() const noexcept
{
  // 返回m_ipcChannel的初始化状态 (Return the initialization status of m_ipcChannel)
  return m_ipcChannel.isInitialized();
}

/**
 * @brief 打开IPC通道 (Open the IPC channel)
 *
 * @tparam IpcChannelType IPC通道类型 (IPC channel type)
 * @param channelSide 通道侧类型 (posix::IpcChannelSide) (Channel side type (posix::IpcChannelSide))
 * @return 是否成功打开 (bool) (Whether it was successfully opened (bool))
 */
template <typename IpcChannelType>
bool IpcInterface<IpcChannelType>::openIpcChannel(const posix::IpcChannelSide channelSide) noexcept
{
  // 设置m_channelSide成员变量 (Set the m_channelSide member variable)
  m_channelSide = channelSide;

  // 创建IPC通道并设置m_ipcChannel (Create the IPC channel and set m_ipcChannel)
  IpcChannelType::create(m_runtimeName, m_channelSide, m_maxMessageSize, m_maxMessages)
    .and_then([this](auto & ipcChannel) { this->m_ipcChannel = std::move(ipcChannel); })
    .or_else([](auto & err) {
      // 打印错误日志 (Print error log)
      IOX_LOG(ERROR) << "unable to create ipc channel with error code: "
                     << static_cast<uint8_t>(err);
    });

  // 返回m_ipcChannel的初始化状态 (Return the initialization status of m_ipcChannel)
  return m_ipcChannel.isInitialized();
}

/**
 * @brief 重新打开IPC通道 (Reopen the IPC channel)
 *
 * @tparam IpcChannelType IPC通道类型 (IPC channel type)
 * @return 是否成功打开 (bool) (Whether it was successfully opened (bool))
 */
template <typename IpcChannelType> bool IpcInterface<IpcChannelType>::reopen() noexcept
{
  // 使用m_channelSide重新打开IPC通道 (Reopen the IPC channel using m_channelSide)
  return openIpcChannel(m_channelSide);
}

/**
 * @brief 判断IPC通道是否映射到文件 (Check if the IPC channel maps to a file)
 *
 * @tparam IpcChannelType IPC通道类型 (IPC channel type)
 * @return 映射状态 (bool) (Mapping status (bool))
 */
template <typename IpcChannelType>
bool IpcInterface<IpcChannelType>::ipcChannelMapsToFile() noexcept
{
  // 返回m_ipcChannel是否过时的否定值 (Return the negation of whether m_ipcChannel is outdated)
  return !m_ipcChannel.isOutdated().value_or(true);
}

// 特化UnixDomainSocket类型的ipcChannelMapsToFile方法 (Specialize the ipcChannelMapsToFile method for UnixDomainSocket type)
template <> bool IpcInterface<posix::UnixDomainSocket>::ipcChannelMapsToFile() noexcept
{
  return true;
}

// 特化NamedPipe类型的ipcChannelMapsToFile方法 (Specialize the ipcChannelMapsToFile method for NamedPipe type)
template <> bool IpcInterface<posix::NamedPipe>::ipcChannelMapsToFile() noexcept { return true; }

/**
 * @brief 判断是否有可关闭的IPC通道 (Check if there is a closable IPC channel)
 *
 * @tparam IpcChannelType IPC通道类型 (IPC channel type)
 * @return 是否可关闭 (bool) (Whether it is closable (bool))
 */
template <typename IpcChannelType>
bool IpcInterface<IpcChannelType>::hasClosableIpcChannel() const noexcept
{
  // 返回m_ipcChannel的初始化状态 (Return the initialization status of m_ipcChannel)
  return m_ipcChannel.isInitialized();
}

/**
 * @brief 清理过期的 IPC 通道（Clean up outdated IPC channels）
 *
 * @tparam IpcChannelType IPC 通道类型（IPC channel type）
 */
template <typename IpcChannelType>
void IpcInterface<IpcChannelType>::cleanupOutdatedIpcChannel(const RuntimeName_t & name) noexcept
{
  // 如果 IPC 通道仍然存在，则尝试取消链接（If the IPC channel still exists, try to unlink it）
  // platform::IoxIpcChannelType::unlinkIfExists 函数返回一个 std::optional<bool>，表示是否成功取消链接（The function platform::IoxIpcChannelType::unlinkIfExists returns an std::optional<bool> indicating whether the unlinking was successful or not）
  if (platform::IoxIpcChannelType::unlinkIfExists(name).value_or(false)) {
    // 如果成功取消链接，记录一条警告日志（If the unlinking is successful, log a warning message）
    IOX_LOG(WARN) << "IPC channel still there, doing an unlink of " << name;
  }
}

// 显式实例化 IpcInterface 类模板，使用 posix::UnixDomainSocket 作为 IPC 通道类型（Explicitly instantiate the IpcInterface class template with posix::UnixDomainSocket as the IPC channel type）
template class IpcInterface<posix::UnixDomainSocket>;
// 显式实例化 IpcInterface 类模板，使用 posix::NamedPipe 作为 IPC 通道类型（Explicitly instantiate the IpcInterface class template with posix::NamedPipe as the IPC channel type）
template class IpcInterface<posix::NamedPipe>;
// 显式实例化 IpcInterface 类模板，使用 posix::MessageQueue 作为 IPC 通道类型（Explicitly instantiate the IpcInterface class template with posix::MessageQueue as the IPC channel type）
template class IpcInterface<posix::MessageQueue>;

} // namespace runtime
} // namespace iox
