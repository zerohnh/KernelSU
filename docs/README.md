# MKSU-SKN
[english](https://github.com/ShirkNeko/KernelSU/edit/susfs/docs/README-en.md) [简体中文](https://github.com/ShirkNeko/KernelSU/edit/susfs/docs/README.md)

基于 [KernelSU](https://github.com/KernelSU/KernelSU) 的安卓设备 root 解决方案

**实验性!使用风险自负!**

>
> 这是非官方分叉，保留所有权利 [@tiann](https://github.com/tiann)

- 已经完全适配非GKI设备,分支为nongki_susfs

## 如何添加
```
curl -LSs "https://raw.githubusercontent.com/ShirkNeko/KernelSU/susfs/kernel/setup.sh" | bash -s susfs
```



## 如何使用 






## 更多链接
基于MKSU-SKN和susfs编译的项目
- [GKI](https://github.com/ShirkNeko/GKI_KernelSU_SUSFS) 
- [一加](https://github.com/ShirkNeko/Action_OnePlus_MKSU_SUSFS)


## 特点

1. 基于内核的 `su` 和 root 访问管理。
2. 非基于 [OverlayFS](https://en.wikipedia.org/wiki/OverlayFS) 的模块系统。
3. [应用程序配置文件](https://kernelsu.org/guide/app-profile.html)： 将 root 权限锁在笼子里。
4. 更多自定义功能
5. 更适合使用习惯的界面和功能



## 许可证

- kernel "目录下的文件是[GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)。
- 除 “kernel ”目录外，所有其他部分均为[GPL-3.0 或更高版本](https://www.gnu.org/licenses/gpl-3.0.html)。

## 贡献

- [KernelSU](https://github.com/tiann/KernelSU)： 原始项目
- [MKSU](https://github.com/5ec1cff/KernelSU)：使用的项目
- [内核辅助超级用户](https://git.zx2c4.com/kernel-assisted-superuser/about/)： KernelSU 的构想
- [Magisk](https://github.com/topjohnwu/Magisk)： 强大的 root 工具
- [genuine](https://github.com/brevent/genuine/)： APK v2 签名验证
- [Diamorphine](https://github.com/m0nad/Diamorphine)： 一些 rootkit 技能
