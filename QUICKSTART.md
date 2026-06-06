# 🚀 Quick Start Guide

## Installation & Setup (60 seconds)

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 2: Run the Interactive UI

```bash
streamlit run app.py
```

The application will open in your browser at `http://localhost:8501`

---

## 📖 Using the Application

### **Tab 1: 🔒 Encryption Sandbox**

- Enter your 64-bit plaintext (hex format, e.g., `48656C6C6F544541`)
- Configure your 128-bit key using K0-K3 inputs
- See real-time encryption/decryption for TEA, MTEA, and XTEA
- Compare ciphertexts across all three algorithms

### **Tab 2: 🚨 Vulnerability Test**

- Click **"Run Equivalent Keys Test"** button
- Watch TEA show as **VULNERABLE** (red badge) ❌
- Watch MTEA show as **SECURE** (green badge) ✅
- Expand details to see the mathematical proof

### **Tab 3: 📈 Analysis**

- Click **"Run Full Analysis"** (takes 30-60 seconds)
- View avalanche effect charts
- See performance metrics for all three algorithms
- Download results as JSON

### **Tab 4: 📊 Comparison**

- View comprehensive comparison matrix
- Read detailed design philosophy explanations
- Check academic references

---

## 🧪 Testing Without Streamlit

### Run Verification Tests

```bash
python test_tea.py
```

This runs all tests and validates:

- ✅ Basic encryption/decryption
- ✅ Equivalent keys vulnerability
- ✅ Avalanche effect analysis
- ✅ Key sensitivity testing
- ✅ Performance benchmarking

### Python API Usage

```python
from tea_core import TEACore, MTEACore, XTEACore
from tea_evaluator import TEAEvaluator

# Encryption/Decryption
plaintext = b"Hello TEA!!!!!!!!"
key = b'0123456789ABCDEF' + b'FEDCBA9876543210'

# TEA Encryption
ciphertext = TEACore.encrypt(plaintext, key)
decrypted = TEACore.decrypt(ciphertext, key)
assert decrypted == plaintext

# Test for Equivalent Keys Vulnerability
evaluator = TEAEvaluator()
result = evaluator.test_equivalent_keys(TEACore, key)
print(result["vulnerable"])  # True for TEA
print(evaluator.test_equivalent_keys(MTEACore, key)["vulnerable"])  # False for MTEA

# Full Analysis
full_results = evaluator.run_full_evaluation(plaintext, key)
```

---

## 🎯 Key Demonstrations

### Equivalent Keys in TEA (Classic Vulnerability)

```python
# Shows that toggling high-order bits produces identical ciphertext
original = TEACore.encrypt(plaintext, key)
modified = TEACore.encrypt(plaintext, modify_key_bits(key))
assert original == modified  # VULNERABLE!
```

### MTEA's Fix

```python
# MTEA uses non-linear key derivation
modified_mtea = MTEACore.encrypt(plaintext, modify_key_bits(key))
assert original != modified_mtea  # SECURE!
```

---

## 📊 Expected Results Summary

| Test                | TEA           | MTEA       | XTEA       |
| ------------------- | ------------- | ---------- | ---------- |
| **Encrypt/Decrypt** | ✅            | ✅         | ✅         |
| **Equivalent Keys** | ❌ Vulnerable | ✅ Secure  | ✅ Secure  |
| **Key Avalanche**   | ~50%          | ~50%       | ~50%       |
| **Performance**     | Fastest       | 59% slower | 33% slower |
| **Code Complexity** | Minimal       | +5%        | +10%       |

---

## 🔍 Advanced Usage

### Adjust Analysis Parameters

- **Avalanche Iterations**: Slider in sidebar (10-100 bit tests)
- **Encryption Rounds**: Adjust from 1-64 (standard: 32)
- **Detailed Results**: Toggle checkbox for expanded information

### Download Results

From the Analysis tab, click **"Download Analysis Results (JSON)"** to save all metrics.

### Custom Testing

Edit the `test_tea.py` file to:

- Change test vectors
- Modify the number of test iterations
- Add custom evaluation metrics

---

## ⚠️ Troubleshooting

| Problem                  | Solution                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| "ModuleNotFoundError"    | Run `pip install -r requirements.txt`                                 |
| Port 8501 already in use | Run `streamlit run app.py --server.port 8502`                         |
| Slow analysis            | Reduce "Avalanche test iterations" in sidebar                         |
| Hex validation error     | Ensure plaintext is 16 hex chars (8 bytes), key is 32 chars per K0-K3 |

---

## 📚 Educational Resources

### Understanding the Concepts

**TEA Vulnerability**:

- Read the "Why TEA is vulnerable" expander in Vulnerability Test tab

**MTEA's Solution**:

- Read the "How MTEA fixes this" expander in Vulnerability Test tab

**Avalanche Effect**:

- See Analysis tab for visual charts
- Learn more in Comparison tab under "Security Properties"

### Running Your Own Tests

```python
# Example: Test a custom plaintext
from tea_core import TEACore
from tea_evaluator import TEAEvaluator

plaintext = b"YourTest"
key = b"YourKeyHere!!!!"  # Pad to 16 bytes

evaluator = TEAEvaluator()
results = evaluator.test_avalanche_effect(TEACore, plaintext, key)
print(f"Avalanche: {results['plaintext_avalanche']['avg_percentage']:.2f}%")
```

---

## ✨ Quick Demo (5 minutes)

1. Run `streamlit run app.py`
2. Go to **Vulnerability Test** tab
3. Click **"Run Equivalent Keys Test"**
4. Observe the red/green badges showing the vulnerability
5. Expand details to see mathematical proof
6. Go to **Analysis** tab
7. Click **"Run Full Analysis"**
8. View performance and avalanche charts
9. Compare all three algorithms in **Comparison** tab

---

## 📞 Support

For issues or questions:

1. Check the README.md for detailed documentation
2. Review inline code comments in `tea_core.py` and `tea_evaluator.py`
3. Run `python test_tea.py` to validate your installation
4. Check the Academic References section in README.md

---

**Ready to explore cryptography? Run `streamlit run app.py` now! 🔐**
