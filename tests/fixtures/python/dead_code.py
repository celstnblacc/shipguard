"""Test fixture for AI Triage Layer. Contains vulnerable code in an unreachable path."""

def active_code():
    print("This code runs.")

def _deprecated_internal_eval_helper(expression):
    # This function is never called anywhere in the codebase.
    # The AI should detect that it's dead code and deprioritize the finding.
    return eval(expression)

if __name__ == "__main__":
    active_code()
