"""
Test script to verify system components are working correctly.
"""
import sys
import os

def test_imports():
    """Test if all required modules can be imported."""
    print("Testing imports...")
    try:
        import numpy
        print("✓ numpy")
    except ImportError as e:
        print(f"✗ numpy: {e}")
        return False
    
    try:
        import pandas
        print("✓ pandas")
    except ImportError as e:
        print(f"✗ pandas: {e}")
        return False
    
    try:
        import tensorflow
        print("✓ tensorflow")
    except ImportError as e:
        print(f"✗ tensorflow: {e}")
        return False
    
    try:
        import flask
        print("✓ flask")
    except ImportError as e:
        print(f"✗ flask: {e}")
        return False
    
    try:
        import flask_socketio
        print("✓ flask-socketio")
    except ImportError as e:
        print(f"✗ flask-socketio: {e}")
        return False
    
    return True

def test_modules():
    """Test if project modules can be imported."""
    print("\nTesting project modules...")
    try:
        from src.tshark_capture import TsharkCapture
        print("✓ TsharkCapture")
    except Exception as e:
        print(f"✗ TsharkCapture: {e}")
        return False
    
    try:
        from src.flow_feature_extractor import FlowFeatureExtractor
        print("✓ FlowFeatureExtractor")
    except Exception as e:
        print(f"✗ FlowFeatureExtractor: {e}")
        return False
    
    try:
        from src.intrusion_detector import IntrusionDetector
        print("✓ IntrusionDetector")
    except Exception as e:
        print(f"✗ IntrusionDetector: {e}")
        return False
    
    try:
        from src.traffic_analyzer import TrafficAnalyzer
        print("✓ TrafficAnalyzer")
    except Exception as e:
        print(f"✗ TrafficAnalyzer: {e}")
        return False
    
    try:
        from src.continual_learning import ContinualLearner
        print("✓ ContinualLearner")
    except Exception as e:
        print(f"✗ ContinualLearner: {e}")
        return False
    
    try:
        from src.web_ui import get_web_ui
        print("✓ WebUI")
    except Exception as e:
        print(f"✗ WebUI: {e}")
        return False
    
    return True

def test_tshark():
    """Test if tshark is accessible."""
    print("\nTesting tshark availability...")
    import subprocess
    
    # Try common paths
    paths = [
        'C:\\Program Files\\Wireshark\\tshark.exe',
        'tshark',
        '/usr/bin/tshark',
        '/usr/local/bin/tshark'
    ]
    
    for path in paths:
        try:
            result = subprocess.run(
                [path, '-v'],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                print(f"✓ tshark found at: {path}")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    
    print("✗ tshark not found. Please install Wireshark.")
    return False

def test_directories():
    """Test if required directories exist."""
    print("\nTesting directories...")
    dirs = ['data', 'models', 'templates', 'static', 'data/prediction_logs']
    
    all_exist = True
    for dir_path in dirs:
        if os.path.exists(dir_path):
            print(f"✓ {dir_path}")
        else:
            print(f"✗ {dir_path} (will be created automatically)")
            all_exist = False
    
    return True  # Not critical, will be created

def main():
    """Run all tests."""
    print("=" * 60)
    print("System Component Tests")
    print("=" * 60)
    
    results = []
    
    results.append(("Imports", test_imports()))
    results.append(("Modules", test_modules()))
    results.append(("Tshark", test_tshark()))
    results.append(("Directories", test_directories()))
    
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    for name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"{name}: {status}")
    
    all_passed = all(result for _, result in results)
    
    if all_passed:
        print("\n✓ All tests passed! System is ready to run.")
        return 0
    else:
        print("\n✗ Some tests failed. Please fix the issues above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())

