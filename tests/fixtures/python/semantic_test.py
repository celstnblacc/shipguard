"""
Semantic Test Fixture for ShipGuard.
This file contains examples that should trick a regex-based scanner but NOT a semantic one.
"""

# 1. False Positive: Object method named 'eval' (Safe)
class SafeCalculator:
    def eval(self, expression: str):
        """This is a safe custom method, not the built-in eval()."""
        print(f"Evaluating safely: {expression}")
        return len(expression)

calc = SafeCalculator()
calc.eval("1 + 1")  # shipguard:ignore PY-003 (current regex engine needs this)

# 2. False Positive: String literal containing 'eval(' (Safe)
message = "To calculate results, use the eval() function."
print(message)

# 3. False Positive: SQL-like string in a harmless f-string (Safe)
# Regex engine might flag 'SELECT' keyword in an f-string as SQL injection.
user_choice = "blue"
status = f"You have SELECTED the color: {user_choice}"
print(status)

# 4. False Positive: Inline comment containing a vulnerable pattern (Safe)
def harmless_func():
    pass # eval(input()) is dangerous, but this is a comment

# 5. True Positive: Actual built-in eval() (Vulnerable)
user_input = "os.system('rm -rf /')"
eval(user_input)
