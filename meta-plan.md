# 工作流程
接下来你要注重恪守基本的设计原则（保持设计简单直接，流畅自然），并且遵循这样的流程来自主工作：
1. 准备一个文件来记录你的工作（.worklog.md），这个文件如果位于代码库，但是绝对不要提交它
2. 当你准备做出一个改动，你需要将你计划的修改，目的，时间，*追加*到这个文件中
3. 当你取得一定阶段的进展，你就进行提交，提交也要追加到这个文件中
4. 当你完成一个功能或者一个阶段的工作，你就进行总结，追加到这个文件中
5. 一切工作记录使用中文，时间使用真实的北京时间

# 远期目标是
完成对genmeta-ssh3的大重构，重构过程中中可以完全抛弃旧有设计决策，思考更加简单，自然，优雅的实现方案并且付诸实践

现有架构逻辑过于分散，并且有严重的架构偏移问题，具有大量复杂的抽象，难以理解和维护

我期望的新架构的样子（你需要达到的目标，旧架构存在的问题）

对于核心库，进行恰当的抽象，需要实现SSH3协议的所有核心功能
1. 发起/接受所有channel的逻辑，包括：session, direct-tcpip, forwarded-tcpip, streamlocal, forwarded-streamlocal（注意：具体的channel type有哪些，需要参考SSH3 RFC, SSH2 RFC, 和那个对UNIX domain sockets 转发的扩展）等
   1. 包括服务端处理session channel的全部流程，客户端发起和维护session channel的全部流程
   2. 包括服务端维护和处理direct-tcpip, forwarded-tcpip, streamlocal, forwarded-streamlocal channel的全部流程，客户端发起和维护direct-tcpip, forwarded-tcpip, streamlocal, forwarded-streamlocal channel的全部流程
2. 和h3x的protocol体系的结合，补全Conversation的创建和管理逻辑
   1. 这里我为你补充部分背景信息，你可以部分参考目前的代码结果进行理解
      1. 这是一个特权分离的设计，主进程（gateway）负责处理所有实际的网络IO, 和子进程之间通过chmoc进行RPC
      2. 现有conversation::remoc::ManageSessionStream是一个RPC接口，SshProtocol结构应该实现h3x::protocol::Protocol trait，然后当ssh3 service接受了一个Extended Connect请求，service可以在SshProtocol上注册得到一个ManageSessionStream的实现，然后通过remoc的能力将这个实现暴露给子进程，子进程通过conversation::remoc::ManageSessionStreamClinet和来自主进程的Remote{Read, Write}Stream（控制流）在子进程创建一个Conversation，并且处理**所有**会话的逻辑
      3. Ssh3Protocol进行路由的流程可以参考h3x对DHttp/3 Protocol的实现，大概是通过Peek来确定接受到的bi流属于SSH3,然后属于哪个会话，然后路由到对应的ManageSessionStream实现上
         1. Ssh3Protocol路由时具体吞噬掉哪些字节，你可以自主决策出边界最清晰的最优解

然后是三个二进制
- 在目前，client,server被分成了两个臃肿复杂的crate，你需要删除这两个crate，对现在的代码结构进行大刀阔斧的重构，大量删除旧的代码结构，将重要逻辑理解优化后 重新设计并实现在核心库 新的代码结构应该非常清晰，简单，直接，优雅
- 每个二进制都应该被控制在一个文件内，因为二进制存在的意义仅仅是整合代码逻辑，核心逻辑全部存在于核心crate中
1. ssh3 session：具体是作为权限分离的子进程存在，通过stdio和主进程（gateway）进行RPC交流，
   1. 它的流程是：
      1. 通过pam进行身份验证，分离特权
      2. 将身份验证结果发送给主进程
      3. 主进程将控制流和ManageSessionStream的RPC handle（Client）发送给子进程
      4. 子进程开始处理所有会话的逻辑，直到会话结束
   2. 上述流程的核心逻辑都应该位于核心库
2. ssh3 client：这是一个ssh3协议的客户端*例子*（只是一个例子）
   1. *代码很少*，更多侧重于对核心库逻辑的整合使用而不是具体是实现复杂逻辑（这应该是核心库的功能）
   2. 如果这个crate的代码很多，说明你的实现出现了偏移
3. ssh3 server：这是一个ssh3协议的服务器*例子*（只是一个例子）
   1. *代码很少*，更多侧重于对核心库逻辑的整合使用而不是具体是实现复杂逻辑（这应该是核心库的功能）
   2. 如果这个crate的代码很多，说明你的实现出现了偏移

# 前置知识（你必须先确认你彻底掌握这些知识，你才可以开始工作）
- 对rust crate的使用：snafu，remoc，nix，tokio，futures
- 对SSH3协议和SSH2协议的理解
- h3x的架构（尤其是protocol体系和codec体系）

# 当前阶段（你可以 也只可以编辑这一部分）

实现长期目标