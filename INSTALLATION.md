# Installation Guide - Advanced Network Anomaly Detection System

**Author**: Aryan Pravin Sahu  
**Institution**: IIT Ropar  
**System**: AI-Powered Cybersecurity Research Platform  

## 📋 **System Requirements**

### **Minimum Requirements:**
- **Operating System**: Windows 10/11, macOS 10.14+, or Linux Ubuntu 18.04+
- **Python**: Version 3.8 or higher
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 2GB free space
- **Internet**: Required for package installation

### **Recommended Requirements:**
- **RAM**: 16GB for optimal performance
- **CPU**: Multi-core processor (4+ cores)
- **GPU**: Optional, for accelerated deep learning (CUDA-compatible)

## 🚀 **Quick Installation (5 Minutes)**

### **Step 1: Install Python**
If Python is not installed:

**Windows:**
1. Download Python from [python.org](https://python.org)
2. Run installer and check "Add Python to PATH"
3. Verify: Open Command Prompt and type `python --version`

**macOS:**
```bash
# Using Homebrew (recommended)
brew install python

# Or download from python.org
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
```

### **Step 2: Clone/Download the System**
```bash
# Option 1: Clone from GitHub
git clone https://github.com/Aryan-Dev26/intelligent-network-analysis.git
cd intelligent-network-analysis

# Option 2: Download ZIP and extract
# Download from GitHub → Extract → Open folder in terminal
```

### **Step 3: Create Virtual Environment (Recommended)**
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate

# macOS/Linux:
source venv/bin/activate
```

### **Step 4: Install Dependencies**
```bash
# Install all required packages
pip install -r requirements.txt

# If you encounter issues, try:
pip install --upgrade pip
pip install -r requirements.txt
```

### **Step 5: Run the System**
```bash
# Start the web dashboard
python src/web/app.py

# Open browser and go to: http://localhost:5000
```

## 🔧 **Detailed Installation Steps**

### **For Windows Users:**

1. **Install Python 3.8+**
   - Download from [python.org](https://python.org)
   - During installation, check "Add Python to PATH"
   - Restart Command Prompt after installation

2. **Download the System**
   ```cmd
   # Open Command Prompt (cmd)
   cd C:\
   git clone https://github.com/Aryan-Dev26/intelligent-network-analysis.git
   cd intelligent-network-analysis
   ```

3. **Set Up Environment**
   ```cmd
   # Create virtual environment
   python -m venv venv
   
   # Activate it
   venv\Scripts\activate
   
   # You should see (venv) in your prompt
   ```

4. **Install Packages**
   ```cmd
   # Upgrade pip first
   python -m pip install --upgrade pip
   
   # Install requirements
   pip install -r requirements.txt
   ```

5. **Run the System**
   ```cmd
   # Start the dashboard
   python src\web\app.py
   
   # Open browser: http://localhost:5000
   ```

### **For macOS Users:**

1. **Install Prerequisites**
   ```bash
   # Install Homebrew (if not installed)
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   
   # Install Python
   brew install python
   
   # Install Git (if not installed)
   brew install git
   ```

2. **Download and Setup**
   ```bash
   # Clone repository
   git clone https://github.com/Aryan-Dev26/intelligent-network-analysis.git
   cd intelligent-network-analysis
   
   # Create virtual environment
   python3 -m venv venv
   source venv/bin/activate
   
   # Install dependencies
   pip install -r requirements.txt
   ```

3. **Run System**
   ```bash
   python src/web/app.py
   # Open: http://localhost:5000
   ```

### **For Linux Users:**

1. **Install Prerequisites**
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install python3 python3-pip python3-venv git
   
   # CentOS/RHEL
   sudo yum install python3 python3-pip git
   ```

2. **Setup System**
   ```bash
   # Clone and setup
   git clone https://github.com/Aryan-Dev26/intelligent-network-analysis.git
   cd intelligent-network-analysis
   
   # Virtual environment
   python3 -m venv venv
   source venv/bin/activate
   
   # Install packages
   pip install -r requirements.txt
   ```

3. **Run System**
   ```bash
   python src/web/app.py
   ```

## 🧪 **Testing the Installation**

### **Basic System Test**
```bash
# Test core functionality
python test_attack_simulations.py

# Expected output: Attack simulation demonstration
```

### **Web Dashboard Test**
1. Start the system: `python src/web/app.py`
2. Open browser: `http://localhost:5000`
3. Click "Run Basic Analysis" - should show results
4. Try "AI Threat Analysis" - should detect threats
5. Test "Attack Simulation" - should show attack patterns

### **API Endpoints Test**
```bash
# Test basic analysis
curl http://localhost:5000/api/basic_analysis

# Test AI features
curl http://localhost:5000/api/ai_threat_analysis
curl http://localhost:5000/api/attack_simulation
```

## 🔍 **Troubleshooting**

### **Common Issues and Solutions:**

#### **Issue 1: "Python not found"**
**Solution:**
- Ensure Python is installed and added to PATH
- Try `python3` instead of `python`
- Restart terminal/command prompt

#### **Issue 2: "Permission denied" (Linux/macOS)**
**Solution:**
```bash
# Use sudo for system-wide installation (not recommended)
sudo pip install -r requirements.txt

# Or use user installation
pip install --user -r requirements.txt
```

#### **Issue 3: "Module not found" errors**
**Solution:**
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Reinstall requirements
pip install -r requirements.txt
```

#### **Issue 4: TensorFlow installation issues**
**Solution:**
```bash
# For older systems, use CPU-only version
pip install tensorflow-cpu

# For systems with GPU
pip install tensorflow-gpu
```

#### **Issue 5: "Port 5000 already in use"**
**Solution:**
- Kill existing process using port 5000
- Or modify `src/web/app.py` to use different port:
```python
app.run(debug=True, port=5001)  # Change port to 5001
```

#### **Issue 6: Slow performance**
**Solution:**
- Reduce packet count in simulations
- Use fewer ML algorithms
- Increase system RAM

### **Package-Specific Issues:**

#### **NumPy/SciPy Issues:**
```bash
# Windows users might need Visual C++ Build Tools
# Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/

# Alternative: Use conda
conda install numpy scipy scikit-learn
```

#### **TensorFlow Issues:**
```bash
# Use specific version
pip install tensorflow==2.13.0

# For Apple Silicon Macs
pip install tensorflow-macos
```

## 📦 **Alternative Installation Methods**

### **Method 1: Using Conda**
```bash
# Install Anaconda/Miniconda first
conda create -n network-analysis python=3.9
conda activate network-analysis
conda install numpy pandas scikit-learn matplotlib flask
pip install tensorflow
```

### **Method 2: Docker Installation**
```bash
# Build Docker image
docker build -t network-analysis .

# Run container
docker run -p 5000:5000 network-analysis
```

### **Method 3: Portable Installation**
For systems where you can't install Python:
1. Download Portable Python
2. Extract to USB drive
3. Copy project files
4. Run from portable environment

## 🎯 **For Demonstration/Presentation**

### **Quick Demo Setup (2 Minutes):**
```bash
# 1. Open terminal in project folder
cd intelligent-network-analysis

# 2. Activate environment (if created)
source venv/bin/activate  # or venv\Scripts\activate on Windows

# 3. Start system
python src/web/app.py

# 4. Open browser: http://localhost:5000
# 5. Ready for demonstration!
```

### **Demo Checklist:**
- [ ] System starts without errors
- [ ] Dashboard loads properly
- [ ] Basic analysis works
- [ ] AI threat analysis shows results
- [ ] Attack simulation displays attacks
- [ ] Real-time processing functions
- [ ] All buttons respond correctly

## 🔒 **Security Considerations**

### **For Production Use:**
- Change default ports
- Enable HTTPS
- Add authentication
- Configure firewall rules
- Use production WSGI server (not Flask dev server)

### **For Research/Demo:**
- Current setup is safe for demonstration
- No real network traffic is captured
- All attacks are simulated
- No external connections made

## 📚 **Additional Resources**

### **Documentation:**
- `README.md` - Project overview
- `docs/research/research_methodology.md` - Research details
- `src/` - Source code with comments

### **Support:**
- GitHub Issues: Report problems
- Email: [Your email for support]
- Documentation: Check inline code comments

## 🎓 **For Academic Use**

### **Citation:**
```
Sahu, A. P. (2024). Advanced Network Anomaly Detection with AI-Powered Threat Intelligence. 
IIT Ropar. https://github.com/Aryan-Dev26/intelligent-network-analysis
```

### **Research Extensions:**
- Real network data integration
- Additional ML algorithms
- Performance optimization
- Scalability improvements

---

## ✅ **Installation Complete!**

Your AI-powered cybersecurity research system is now ready for:
- **Research and development**
- **Academic presentations**
- **MS application demonstrations**
- **Further enhancement and customization**

**Next Steps:**
1. Explore the dashboard features
2. Run attack simulations
3. Analyze AI explanations
4. Customize for your research needs

**Support**: If you encounter any issues, check the troubleshooting section or create an issue on GitHub.