import sys

# project number
num_proj = (int)(sys.argv[1])

# number of iterations
num_iter = (int)(sys.argv[2])

# result directory
res_dir = sys.argv[3]

# number of tests
num_tests = {1 : 27, 2 : 80, 3 : 113, 4 : 125}
num_test = num_tests[num_proj]

# print failed test name for each make check result
num_digit = len(str(num_iter))
for i in range(num_iter):
    file_name = res_dir + '/make_check_' + str(i + 1) + '.txt'
    with open(file_name) as f:
        print('************** Result ' + str(i + 1).zfill(num_digit) + ' **************')
        lines = f.readlines()
        print(lines[-2], end='')
        lines = lines[-(num_test+2):-3]
        for line in lines:
            words = line.split()
            if words[0] == 'FAIL':
                print(line, end='')
        print(end='\n')
