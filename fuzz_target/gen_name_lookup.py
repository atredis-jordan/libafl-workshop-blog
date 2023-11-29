import random
import string


# names from https://data.cityofnewyork.us/api/views/25th-nujf/rows.csv?accessType=DOWNLOAD



def gen_name_arr(names):
    p = "const char* names[] = {\n"
    for n in names:
        p += f"\t\"{n}\",\n"
    p += "};\n"

    return p
    

uid_chars = string.digits + string.ascii_letters + "_-"

def gen_tree(uid_len, max_depth, count, num_names, vulnchance, depth=0, constraints=None):

    depth = depth + 1

    t = '\t' * depth

    if constraints is None:
        # constraints[<byte_index>] = (val|None)
        constraints = {x: None for x in range(uid_len)}

    left = [x for x in constraints.keys() if constraints[x] is None]

    if (depth >= max_depth) or (len(left) == 0):
        example = ''.join(['?' if constraints[x] is None else constraints[x] for x in range(uid_len)])
        nameindex = random.randrange(num_names)

        p = ""
        p += f"{t}// {example}\n"
        if random.random() < vulnchance:
            p += f"{t}addr = ((const char**)0x{random.randrange(0x10000):x});\n"
        else:
            p += f"{t}addr = &names[0x{nameindex:x}];\n"
        
        p += f'{t}LOG("UID matches known name at %p", addr);\n'
        p += f'{t}return *addr;\n'
        return p

    test_index = random.choice(left)

    p = f"{t}switch (nbuf[{test_index}]) {{\n"

    if count < 2:
        count = 2

    vleft = list(uid_chars)
    for _ in range(count):
        vi = random.randrange(len(vleft))
        v = vleft[vi]
        del vleft[vi]

        c = constraints.copy()
        c[test_index] = v

        p += f"{t}case '{v}':\n"
        p += gen_tree(uid_len, max_depth, count, num_names, vulnchance, depth, c)

    p += f"{t}default:\n"
    p += f"{t}\treturn NULL;\n"
    p += f"{t}}}\n"

    return p

def main():


    # we should balance the tree as much as possible, looking for bytes where we can get the most even tree?
    # we could do this by generating the var names when generating the tree

    with open("names.txt", "r") as fp:
        names = fp.read().split('\n')

    prog = ""

    prog += gen_name_arr(names)

    uid_len = 16

    prog+= f"""
#define UID_LEN 0x{uid_len:x}

const char* uid_to_name(const char* uid) {{
    const char** addr;
    char nbuf[UID_LEN] = {{0}};
    memcpy(nbuf, uid, UID_LEN);

"""

    random.seed(42)

    prog += gen_tree(uid_len, max_depth=6, count=8, num_names=len(names), vulnchance=0.15)

    prog += "}\n";
    print(prog)

if __name__ == '__main__':
    main()
