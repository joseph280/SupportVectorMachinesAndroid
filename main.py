#                            Joseph Aguilar Feener
#                                  18/11/2017
#      Support Vector Machines applied to Malware recognition in Android OS.

import os
import psutil
import time
import numpy as np
from tkinter import *


path = '/home/joseph/Documents/AI/MachineLearning/MalwareDetection/drebin/feature_vectors/'
path_malware = '/home/joseph/Documents/AI/MachineLearning/MalwareDetection/drebin/sha256_family.csv'
target_path = '/home/joseph/Documents/AI/MachineLearning/MalwareDetection/drebin/malwareDB3.arff'
# 129013 values in the Android malware dataset

s2_permission_string = 'App requests permission to access %s.'
s4_intent_string = 'Action is triggered by %s.'
s7_call_string = 'App uses suspicious API call %s.'

features = ['permission', 'intent', 'call']  # S2, S4 and S7
LIMIT = 18000
joint_set = []

start_time = time.time()


def validation_method_choose():
    text = input_validation.get()
    if text == 'RS':
        mEntry = Entry(mGui, textvariable=percentage_sets).pack()
        mButton = Button(mGui, text='Insert', command=main_execution_random_sampling, fg='black', bg='white').pack()
    elif text == 'KF':
        mEntry = Entry(mGui, textvariable=n_folds).pack()
        mButton = Button(mGui, text='Insert', command=main_execution_k_folds, fg='black', bg='white').pack()
        n_folds.set(5)
    else:
        mLabel2 = Label(mGui, text='Sorry, validation method not found. Retry please.').pack()
    return


def main_execution_random_sampling():
    c = 0
    mw_db = [[], []]

    with open(path_malware) as fm:
        db_malware = fm.read()
        db_malware_lines = db_malware.splitlines()
        for mw in db_malware_lines:
            mw_code = mw.split(',')
            if mw_code[0] != 'sha256':
                mw_db[0].append(mw_code[0])
                mw_db[1].append(mw_code[1])
    # print(mw_db)

    for filename in os.listdir(path):
        # print('FILENAME '+filename)
        if c >= LIMIT:
            break
        if c % 10000 == 0:
            print('This is c: ' + str(c))
            print(psutil.cpu_freq())
            print(psutil.virtual_memory())
            print(psutil.swap_memory())
            print('Elapsed time: '+str(time.time() - start_time))
        c += 1
        f = open(path+filename)
        try:
            sample = f.read()
            sample_lines = sample.splitlines()
            for line in sample_lines:
                feature_val = line.split('::')
                if len(feature_val) >= 2:
                    if feature_val[0] in features:
                        # if feature_val[1].__contains__('BOOT'):
                        #     print('.')
                        #     print(feature_val[0])
                        #     print(feature_val[1])
                        # joint_set[feature_val[1]] = False
                        # Dictionary version up, list version down
                        if feature_val[1] not in joint_set:
                            joint_set.append(feature_val[1])
                else:
                    print('Feature with wrong format.')
        finally:
            f.close()

        # print('\n')
    print('***')
    print(str(c))
    print(str(len(joint_set)))
    print(str(joint_set))
    print('!!!')
    # print(str(mw_db[0]))

    # WRITING ARFF FILE

    c, kk = 0, 0
    ft = open(target_path, 'w')
    ft.write('@relation malware\n')
    for y in range(len(joint_set)):
        kk += 1
        ft.write('@attribute a'+str(kk)+'{1, 0}\n')
    ft.write('@attribute class {1, 0}\n')
    ft.write('@data\n')

    for filename2 in os.listdir(path):
        # print('FILENAME2 '+filename2)
        if filename2 in mw_db[0]:
            new_db_line = [1]  # It is Malware
            # print('GOT ONE')
        else:
            new_db_line = [0]  # It is safe
        for t in range(len(joint_set)):
            new_db_line.append(0)
        if c >= LIMIT:
            print(str(c))
            break
        # print(new_db_line)

        if c % 10000 == 0:
            print('This is c: ' + str(c))
            print(psutil.cpu_freq())
            print(psutil.virtual_memory())
            print(psutil.swap_memory())
            print('Elapsed time: '+str(time.time() - start_time))

        c += 1

        f = open(path + filename2)
        try:
            sample = f.read()
            sample_lines = sample.splitlines()
            for line in sample_lines:
                feature_val = line.split('::')
                if len(feature_val) >= 2:
                    if feature_val[0] in features:
                        if feature_val[1] in joint_set:
                            new_db_line[joint_set.index(feature_val[1])+1] = 1
                            # print('Index. '+str(joint_set.index(feature_val[1])+1))
                else:
                    print('Feature with wrong format.')
        finally:
            f.close()
        for val in range(len(new_db_line)-1):
            ft.write(str(new_db_line[val])+', ')
        ft.write(str(new_db_line[-1])+'\n')
    print(str(len(new_db_line)))
    print(str(len(joint_set)))
    print('the end')
    ft.close()

    return


def main_execution_k_folds():
    dict_actual, prob_spam_vec, prob_ham_vec, spam, ham = [], [], [], [], []

    return


mGui = Tk()
n_folds = IntVar()
percentage_sets = IntVar()
input_validation = StringVar()
v = IntVar()
mGui.geometry('550x450+500+300')
mGui.title(' Support Vector Machines applied to Malware recognition in Android OS.')
mLabel = Label(mGui, text='Please insert the validation method (Random Sampling / K-folds): ').pack()
Radiobutton(mGui, text="Random Sampling", variable=input_validation, value='RS').pack(anchor=W)
Radiobutton(mGui, text="K-Folds", variable=input_validation, value='KF').pack(anchor=W)
input_validation.set('RS')

mButton = Button(mGui, text='Insert', command=validation_method_choose, fg='black', bg='white').pack()
mGui.mainloop()
