# decaf
本次上传版本主要完成了以下工作：
1、完成了DECAF的VMI功能在QEMU6.2上的实现，目前能在运行linux内核为3.2-4.4的系统时获取进程、模块等信息，且实现了block级别的插桩；
2、在QEMU6.2的TCG语言层面实现了污点分析规则，其中部分规则延用了DECAF的标准并对其中一部分进行了精确性优化，对于QEMU6.2的新指令自行设计了污点传播规则；
3、延用了DECAF中的影子内存设计，但重新设计了影子内存和TCG执行时污染标记的传播流程（还需要进行准确性验证）。