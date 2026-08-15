# Windows 上传到 GitHub

目标仓库：`https://github.com/SectorPace/MailStack`

1. 解压完整包到 `D:\MailStack`。
2. 安装 Git for Windows。
3. 在该目录右键选择 **Open Git Bash here**。
4. 执行：

```bash
git init
git branch -M main
git config user.name "SectorPace"
git config user.email "你的 GitHub 邮箱"
git remote add origin https://github.com/SectorPace/MailStack.git
git add .
git status
git commit -m "Release MailStack v0.1-beta1"
git tag -a v0.1-beta1 -m "MailStack v0.1-beta1"
git push -u origin main
git push origin v0.1-beta1
```

如果已有 origin：

```bash
git remote set-url origin https://github.com/SectorPace/MailStack.git
```

如果远程已有初始化 README：

```bash
git pull origin main --allow-unrelated-histories
git push -u origin main
```
