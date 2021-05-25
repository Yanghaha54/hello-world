QOM

QOM是QEMU在C的基础上自己实现的一套面向对象机制，负责将几乎所有的设备如cpu、内存、总线等等等都抽象成为对象。通过QOM，qemu能够对各种资源进行抽象和管理，毫不夸张的说，QOM遍布于qemu代码。

对象的初始化分为四步：

1. 将 TypeInfo 注册 TypeImpl
2. 实例化 ObjectClass
3. 实例化 Object
4. 添加 Property

以上几个结构体都是QOM中关键的结构体，接下来我们结合qemu源码（6.0版本）对以上过程进行分析(为了更方便理解，我们会以具体实例为例进行说明）。

**TypeInfo注册&&模块注册**

首先我们看一下TypeInfo这个结构体：

```c
struct TypeInfo
{
    const char *name;				//type名字
    const char *parent;			//parent type名字

    size_t instance_size;		//object大小
    size_t instance_align;	
    void (*instance_init)(Object *obj);		//Object初始化函数
    void (*instance_post_init)(Object *obj);		//完成Object初始化函数，在instance_init之后
    void (*instance_finalize)(Object *obj);		//Object销毁时被调用的函数

    bool abstract;					//class是否能被抽象
    size_t class_size;			//class object大小

    void (*class_init)(ObjectClass *klass, void *data);		//父类初始化完成后被调用重写函数
    void (*class_base_init)(ObjectClass *klass, void *data);	//所有基类初始化
    void *class_data;				//class_init的数据

    InterfaceInfo *interfaces;		//该type关联的接口列表
};
```

用户会对TypeInfo结构体进行实现，对应到标准的usb设备驱动中对这个结构体实现：

```c
static const TypeInfo ehci_pci_type_info = {
    .name = TYPE_PCI_EHCI,
    .parent = TYPE_PCI_DEVICE,
    .instance_size = sizeof(EHCIPCIState),
    .instance_init = usb_ehci_pci_init,
    .instance_finalize = usb_ehci_pci_finalize,
    .abstract = true,
    .class_init = ehci_class_init,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    },
};
```

TypeInfo对象定义完成之后会将该对象注册到TypeImp中，具体流程：

```c
static void ehci_pci_register_types(void)
{
    TypeInfo ehci_type_info = {
        .parent        = TYPE_PCI_EHCI,
        .class_init    = ehci_data_class_init,
    };
    int i;

    type_register_static(&ehci_pci_type_info);

    for (i = 0; i < ARRAY_SIZE(ehci_pci_info); i++) {
        ehci_type_info.name = ehci_pci_info[i].name;
        ehci_type_info.class_data = ehci_pci_info + i;
        type_register(&ehci_type_info);
    }
}

//中间过程：type_register_static -> type_register(info) ->type_register_internal(info)

static TypeImpl *type_register_internal(const TypeInfo *info)
{
    TypeImpl *ti;
    ti = type_new(info);		//对info的信息写入TypeImpl

    type_table_add(ti);			//将新的type插入到type表
    return ti;
}
```

至此，TypeInfo注册完毕，生成了相应的TypeImp实例，并将TypeInfo注册到全局的TypeImpl的hash表。然后，每个对象初始化的文件底部有一个函数对type进行初始化：

```c
type_init(ehci_pci_register_types);
```

`type_init()`的作用就是向QOM模块注册自己，注册过程：

```c
type_init(register_accel_types)
	-->module_init(function, MODULE_INIT_QOM)
		-->register_module_init(void (*fn)(void), module_init_type type)
  
void register_module_init(void (*fn)(void), module_init_type type)
{
    ModuleEntry *e;
    ModuleTypeList *l;

    e = g_malloc0(sizeof(*e));	
    e->init = fn;							//将register_accel_types作为模块入口初始化函数
    e->type = type;						

    l = find_type(type);			//查找MODULE_INIT_QOM

    QTAILQ_INSERT_TAIL(l, e, node);		//将e加入到 MODULE_INIT_QOM 的 ModuleTypeList 中
}
```

在qemu启动过程中：

```
main()
	-->qemu_init()
		-->qemu_init_subsystems()
			-->module_call_init(MODULE_INIT_QOM)
```

会通过module_call_init()函数从init_type_list中取出对应的 ModuleTypeList ，然后对里面的 ModuleEntry 成员都调用 init 函数。

**Class初始化&&ObjectClass实例化**

经过模块注册的过程会得倒一个TypeImpl的哈希表，下一步就是初始化每个type，也可以看作是class初始化，可以理解成每一个type对应了一个class，TypeImpl对应的结构体：

```c
struct TypeImpl
{
    const char *name;

    size_t class_size;

    size_t instance_size;
    size_t instance_align;

    void (*class_init)(ObjectClass *klass, void *data);
    void (*class_base_init)(ObjectClass *klass, void *data);

    void *class_data;

    void (*instance_init)(Object *obj);
    void (*instance_post_init)(Object *obj);
    void (*instance_finalize)(Object *obj);

    bool abstract;

    const char *parent;
    TypeImpl *parent_type;

    ObjectClass *class;

    int num_interfaces;
    InterfaceImpl interfaces[MAX_INTERFACES];
};
```

初始化过程：

```c
main()
	-->qemu_init()
		-->qemu_create_machine()
			-->select_machine()
				-->object_class_get_list()
					-->object_class_foreach()
						-->g_hash_table_foreach(type_table_get(), object_class_foreach_tramp, &data)
							-->object_class_foreach_tramp()
							-->type_initialize()
```

type_initialize()对每个type进行初始化，包括class的内存分配和初始化等等：

```c
static void type_initialize(TypeImpl *ti)
{
    TypeImpl *parent;

    if (ti->class) {		//已经初始直接返回
        return;
    }

    ti->class_size = type_class_get_size(ti);
    ti->instance_size = type_object_get_size(ti);
  
    if (ti->instance_size == 0) {
        ti->abstract = true;
    }
    if (type_is_ancestor(ti, type_interface)) {
        ......
    }
    ti->class = g_malloc0(ti->class_size);	//分配class内存

    parent = type_get_parent(ti);
    if (parent) {								//判断ti的parent是否存在
        type_initialize(parent);			//parent存在则递归调用type_initialize对其进行初始化
        ......
        memcpy(ti->class, parent->class, parent->class_size);
        ti->class->interfaces = NULL;
				......
    }

    ti->class->properties = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
                                                  object_property_free);

    ti->class->type = ti;

    while (parent) {
        if (parent->class_base_init) {
            parent->class_base_init(ti->class, ti->class_data);
        }
        parent = type_get_parent(parent);
    }

  	//判断设备TypeInfo结构体是否存在class_init函数，存在则调用做进一步ObjectClass初始化
    if (ti->class_init) {
        ti->class_init(ti->class, ti->class_data);
    }
}
```

http://juniorprincewang.github.io/2018/07/23/qemu%E6%BA%90%E7%A0%81%E6%B7%BB%E5%8A%A0%E8%AE%BE%E5%A4%87/

https://terenceli.github.io/%E6%8A%80%E6%9C%AF/2017/01/08/qom-introduction

https://www.binss.me/blog/qemu-note-of-qemu-object-model/
