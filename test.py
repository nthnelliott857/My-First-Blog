import hashlib
result = hashlib.md5(b' John@gmail.com'.strip().lower())
print(result.digest())
