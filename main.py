"""
Code Injection Techniques Database
Educational security research tool — entry point.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import InjectionTechniqueDB

if __name__ == "__main__":
    app = InjectionTechniqueDB()
    app.mainloop()
