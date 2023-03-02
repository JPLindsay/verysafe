"""This script demonstrates a bug in whereby Snyk trusts an unsanitized string
touched by Python's re.match() function."""

# If you wish to test the assertion near the end of this script, run:
#
#   yes 1 | python3 poc.py
#
# This will fill the input with a singular numeral 1, which Python will safely
# evaluate.
#
# Note that there are three unsafe calls to eval. If you run it manually, be
# careful about what you type in the unlabeled inputs.

import copy
import re

# First, demonstrate correct handling

i = input()
eval(i)  # Snyk correctly identifies the code injection vulnerability

# Make a copy of the input for use in an upcoming assertion.
# Python strings are immutable, so `i_cpy = i` would suffice here. Just to
# remove any doubt, however, we'll make an extra-explicit copy.
i_cpy = copy.deepcopy(i)

# Next, pass the input through re.match()
#
# re.match() is a nearly pure function. The function returns an re.Match object
# or None if no match was found. Importantly, the input string is left
# unchanged, which we'll prove later.
#
# Importantly, we don't use the match object. Snyk has no reason to think that
# the input has been sanitized.
#
# This is *NOT* a test of Snyk's ability to analyze regex-based sanitization.
_ = re.match(r"(.*)", i)
eval(i)  # Snyk should flag this but doesn't

# Prove that the input wasn't modified by testing equality against the copy
assert i == i_cpy

# Snyk understands that i_cpy is a copy of unsanitized input and correctly
# flags this eval as unsafe.
eval(i_cpy)

# EXPECTED OUTPUT OF `snyk code test`:
#
# 3 High: Code Injection
#
# ACTUAL OUTPUT:
#
# 2 High: Code Injection