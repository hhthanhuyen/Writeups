from typing import List
import random

def get_permutation(n : int) -> List[int]:
    arr = list(range(n))
    random.shuffle(arr)
    return arr

def compose_permutation(p1 : List[int], p2 : List[int]):
    return [p1[x] for x in p2]

def permutation_power(p : List[int], n : int) -> List[int]:
    if n == 0:
        return list(range(len(p)))
    if n == 1:
        return p

    x = permutation_power(p, n // 2)
    x = compose_permutation(x, x)
    if n % 2 == 1:
        x = compose_permutation(x, p)
    return x


with open("flag.txt", "rb") as f:
    flag = int.from_bytes(f.read().strip(), byteorder='big')

perm = get_permutation(512)
print(perm)
print(permutation_power(perm, flag))