
# ShowTime - 透明窗口时光追踪器

![主界面截图](https://github.com/liaanj/ShowTime/blob/main/doc/image.png)
*主界面显示解锁时间和应用使用时间。*

**ShowTime** 是一款基于 PySide6 开发的 Windows 专用透明窗口应用，旨在帮助用户追踪系统解锁时间和当前应用的使用时长。通过智能的全屏检测与隐藏功能，ShowTime 为您的时间管理提供直观且不干扰的支持，让您更高效地掌控每一分每一秒。

## 软件推荐

在快节奏的现代生活中，我们常常会发现自己在不知不觉中浪费了大量时间。例如，您可能会在 B 站刷视频，一个小时的娱乐时间很快就过去了，却没有任何实际收获。这样的时间浪费不仅影响了工作和学习效率，还可能导致生活质量的下降。

**ShowTime** 正是为了解决这些问题而设计的。它通过透明窗口的形式，实时显示您自上次解锁系统以来的时间和当前应用程序的使用时长，帮助您时刻关注自己的时间分配，避免无意识的时间浪费。无论是工作中的高效利用，还是娱乐时的自律管理，ShowTime 都能成为您的得力助手。

### 为什么选择 ShowTime？

- **实时监控**：清晰展示解锁时间和应用使用时长，让您时刻了解自己的时间分配情况。
- **智能隐藏**：在全屏应用启动时自动隐藏窗口，避免干扰您的工作或娱乐体验。
- **高度可定制**：多种外观设置，包括字体大小、颜色、窗口尺寸、进度条颜色与位置，满足您的个性化需求。
- **提醒功能**：根据设定的时间提醒您，帮助您及时调整使用习惯，提升时间管理能力。
- **开机自启**：可选择设置程序开机自动启动，随时随地掌控您的时间。
- **多屏幕支持**：优化多显示器环境，仅在主屏幕上下边缘进行窗口隐藏，确保操作便捷。

通过 **ShowTime**，您可以有效减少在无意义应用上的时间投入，提升工作和生活的效率与质量。立即下载并体验 ShowTime，让时间管理变得更加轻松高效！

## 主要功能

- **解锁时间追踪**：实时记录自上次解锁系统以来的时间。
- **应用使用时间追踪**：追踪当前活跃应用程序的使用时长。
- **全屏隐藏模式**：在全屏应用启动时自动隐藏窗口，避免干扰。
- **提醒功能**：根据解锁时间或应用使用时间设置提醒通知。
- **自定义外观设置**：
  - 字体大小与颜色
  - 窗口尺寸与位置
  - 进度条颜色与位置
- **开机自启**：可选择设置程序开机自动启动。
- **多屏幕支持**：支持多显示器环境，仅在主屏幕上下边缘进行窗口隐藏。

## 截图

### 主界面

![主界面](https://github.com/您的用户名/ShowTime/raw/main/screenshots/main_interface.png)
*主界面显示解锁时间和应用使用时间。*

### 设置界面

![设置界面](https://github.com/您的用户名/ShowTime/raw/main/screenshots/settings_interface.png)
*设置界面允许用户自定义外观和功能。*

### 提醒设置

![提醒设置](https://github.com/您的用户名/ShowTime/raw/main/screenshots/reminder_settings.png)
*提醒设置界面，帮助用户配置提醒通知。*

## 安装指南

### 前置条件

- **操作系统**：Windows 10 或更高版本
- **Python**：Python 3.7+
- **依赖库**：
  - PySide6
  - psutil
  - pywin32

### 安装步骤

1. **克隆仓库**

   ```bash
   git clone https://github.com/您的用户名/ShowTime.git
   cd ShowTime
   ```

2. **创建虚拟环境（可选）**

   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

3. **安装依赖**

   ```bash
   pip install -r requirements.txt
   ```

4. **运行程序**

   ```bash
   python showtime.py
   ```

## 使用指南

1. **启动程序**：双击运行 `showtime.py` 或在命令行中执行 `python showtime.py`。
2. **主界面**：程序启动后会在屏幕上显示一个透明窗口，展示解锁时间和当前应用的使用时间。
3. **右键菜单**：右键点击窗口，打开上下文菜单，提供以下选项：
   - 清除时间
   - 设置提醒
   - 外观设置
   - 暂停/继续计时
   - 开机自启
   - 全屏隐藏
   - 退出应用
4. **设置提醒**：通过右键菜单中的“设置提醒”选项，您可以根据解锁时间或应用使用时间设置提醒。
5. **外观设置**：在“外观设置”中，您可以自定义字体大小、颜色、窗口尺寸、进度条颜色等。
6. **全屏隐藏**：在设置中启用“全屏隐藏”，程序将在全屏应用启动时自动隐藏，避免干扰您的使用体验。

## 配置说明

程序会在用户主目录下创建一个配置文件 `.my_app_config.json`，保存用户的个性化设置。您可以通过以下方式进行配置：

- **通过程序界面**：使用外观设置界面进行修改，所有设置会自动保存到配置文件中。
- **手动编辑**：直接编辑配置文件 `.my_app_config.json`，调整窗口位置、尺寸、颜色等参数。请确保输入的数值和颜色代码格式正确。

## 贡献指南

欢迎任何形式的贡献！您可以通过以下方式参与：

- **提交问题**：在 GitHub 问题区报告 Bug 或提出改进建议。
- **提交拉取请求**：修复 Bug 或添加新功能，请确保代码质量和文档完整。
- **提出建议**：在讨论区分享您的想法和建议，帮助我们改进 ShowTime。

### 贡献步骤

1. **Fork 仓库**
2. **创建分支**

   ```bash
   git checkout -b feature/新功能
   ```

3. **提交更改**

   ```bash
   git commit -m "添加了新功能"
   ```

4. **推送到分支**

   ```bash
   git push origin feature/新功能
   ```

5. **创建 Pull Request**

## 许可证

本项目采用 MIT 许可证。详情请参阅 [LICENSE](https://github.com/您的用户名/ShowTime/blob/main/LICENSE) 文件。

## 联系方式

如有任何问题或建议，请通过以下方式联系我：

- **GitHub Issues**：在 [Issues](https://github.com/您的用户名/ShowTime/issues) 区提交。
- **电子邮件**：发送邮件至 [your_email@example.com](mailto:your_email@example.com)。
