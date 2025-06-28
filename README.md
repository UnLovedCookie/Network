<h1 align="center">
🚀 Network Optimization Script
</h1>
<h3 align="center">
Improve the throughput and reduce latency by optimizing the Windows network stack.
</h3>
<p align="center">
<i>“Simply put, Windows isn't optimized for the lowest possible latency and greatest performance. It's optimized for best compatibility, power efficiency, and stability.”</i>
</p>

---
## 📥 Installation

### ⚡ Quick Install via PowerShell

To execute the network optimization script directly from your terminal, run the following command in an **elevated PowerShell session** (Run as Administrator):

```powershell
irm https://raw.githubusercontent.com/UnLovedCookie/Network/refs/heads/main/Network.ps1 | iex
```



This command performs the following actions:

* **Downloads** the latest version of the `Network.ps1` script from the official GitHub repository.
* **Executes** the script immediately, applying the network optimizations.
* **Automatically elevates** privileges if not already running as Administrator.

> ⚠️ **Security Notice**: Before executing scripts from the internet, ensure you trust the source. You can review the script's content [here](https://github.com/UnLovedCookie/Network/blob/main/Network.ps1) before running it.

### 🛠️ Manual Installation

If you prefer to inspect the script before execution:

1. **Download the Script**:

   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/UnLovedCookie/Network/refs/heads/main/Network.ps1" -OutFile "Network.ps1"
   ```



2. **Review the Script**:

   Open `Network.ps1` in your preferred text editor to examine its contents.

3. **Run the Script**:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Network.ps1
   ```



> 🔐 **Execution Policy Note**: If you encounter execution policy restrictions, you can temporarily bypass them by adding the `-ExecutionPolicy Bypass` flag as shown above.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 💬 Community & Support

* **Discord Server:** [Join the Community](https://discord.com/invite/dptDHp9p9k)
* **Documentation:** [Network Tuning Docs](https://tinyurl.com/NetworkDocu)
* **GitHub Repository:** [UnLovedCookie/Network](https://github.com/UnLovedCookie/Network)

---

*Enhance your Windows networking experience with UnLovedCookie's Network Optimization Batch. Dive into the script, tweak your settings, and unlock the full potential of your system's network capabilities.*

---

[1]: https://github.com/UnLovedCookie/Network?utm_source=chatgpt.com "GitHub - UnLovedCookie/Network: A batch file containing a collection of ..."
[2]: https://github.com/UnLovedCookie/Network/releases?utm_source=chatgpt.com "Releases · UnLovedCookie/Network · GitHub"
[3]: https://github.com/UnLovedCookie/?utm_source=chatgpt.com "UnLovedCookie (aiden) · GitHub"
