
# ShowTime - 时光追踪器

<div align=center>
<img src="https://github.com/liaanj/ShowTime/blob/main/doc/icons.ico" width="170px">
</div>
<p></p><p></p>

**ShowTime** 是一款基于 PySide6 开发的 Windows 的应用，旨在帮助用户追踪系统解锁时间和当前应用的使用时长。

在快节奏的现代生活中，我们常常会发现自己在不知不觉中浪费了大量时间。例如，您可能会在 B 站刷视频，一个小时的娱乐时间很快就过去了，却什么事都没干。

**ShowTime** 正是为了解决这些问题而设计的。它通过任务栏透明窗口的形式，实时显示您自上次解锁系统以来的时间和当前应用程序的使用时长，帮助您时刻关注自己的时间分配，避免无意识的时间浪费。无论是工作中的高效利用，还是娱乐时的自律管理，ShowTime 都能成为您的得力助手。


### 为什么选择 ShowTime？

- **实时监控**：清晰展示解锁时间和应用使用时长，让您时刻了解自己的时间分配情况。
- **智能隐藏**：在全屏应用启动时可以手动拖动窗口到边缘来隐藏或自定义窗口位置，避免干扰您的工作或娱乐体验。
- **高度可定制**：多种外观设置，包括字体大小、颜色、窗口尺寸、进度条颜色与位置，满足您的个性化需求。
- **提醒功能**：根据设定的时间提醒您，帮助您及时调整使用习惯，提升时间管理能力。
- **开机自启**：可选择设置程序开机自动启动，随时随地掌控您的时间。

通过 **ShowTime**，您可以有效减少在无意义应用上的时间投入，提升工作和生活的效率与质量。立即下载并体验 ShowTime，让时间管理变得更加轻松高效！

### 主界面

<p >
  <img src="https://github.com/liaanj/ShowTime/blob/main/doc/mainwin1.png" width="180px">
  <img src="https://github.com/liaanj/ShowTime/blob/main/doc/mainwin4.PNG" width="280px">
  <img src="https://github.com/liaanj/ShowTime/blob/main/doc/mainwin6.png" width="280px">
</p>


<p></p><p></p>

*主界面显示解锁时间和应用使用时间*

### 设置界面

<img src="https://github.com/liaanj/ShowTime/blob/main/doc/appsetting.png" width="270px">

*设置界面允许用户自定义外观和功能*

### 提醒设置

<img src="https://github.com/liaanj/ShowTime/blob/main/doc/time.png" width="270px">

*提醒设置界面，帮助用户配置提醒通知。*

## 使用指南

1. **启动程序**：双击运行 `showtime.exe` 或在命令行中执行 `python showtime.py`。
2. **主界面**：程序启动后会在屏幕上显示一个透明窗口，展示解锁时间和当前应用的使用时间，拖动将其放到合适的地方。
3. **右键菜单**：右键点击窗口，打开上下文菜单，提供以下选项：
   - 清除时间
   - 设置提醒
   - 外观设置
   - 暂停/继续计时
   - 开机自启
   - 退出应用
   - 关于软件
4. **设置提醒**：通过右键菜单中的“设置提醒”选项，您可以根据解锁时间或应用使用时间设置提醒。
5. **外观设置**：在“外观设置”中，您可以自定义字体大小、颜色、窗口尺寸、进度条颜色等。
6. **全屏隐藏**：在全屏状态下，程序会自动记录您所拖动到的位置，或者可以将其拖动到屏幕边缘以进行隐藏。在位置出问题的时候可以打开配置文件调整位置并重启软件。

## 配置说明

程序会在用户主目录下创建一个配置文件 `.my_app_config.json`，保存用户的个性化设置。您可以通过以下方式进行配置：

- **通过程序界面**：使用外观设置界面进行修改，所有设置会自动保存到配置文件中。
- **手动编辑**：直接编辑配置文件 `.my_app_config.json`，调整窗口位置、尺寸、颜色等参数。请确保输入的数值和颜色代码格式正确。

## 贡献指南

欢迎任何形式的贡献！您可以通过以下方式参与：

- **提交问题**：在 GitHub 问题区报告 Bug 或提出改进建议。
- **提交拉取请求**：修复 Bug 或添加新功能，请确保代码质量和文档完整。
- **提出建议**：在讨论区分享您的想法和建议，帮助我们改进 ShowTime。


## 许可证

本项目采用 MIT 许可证。详情请参阅 [LICENSE](https://github.com/liaanj/ShowTime/blob/main/LICENSE) 文件。

