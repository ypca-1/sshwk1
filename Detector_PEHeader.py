#!/usr/bin/python
# -*- coding: utf-8 -*-


import os
import sys
import pickle
import argparse
import re

import numpy
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import FeatureHasher

import pefile

HEADER = ['Magic',
          'MajorLinkerVersion',
          'MinorLinkerVersion',
          'SizeOfCode',
          'SizeOfInitializedData',
          'SizeOfUninitializedData',
          'AddressOfEntryPoint',
          'BaseOfCode',
          'BaseOfData',
          'ImageBase',
          'SectionAlignment',
          'FileAlignment',
          'MajorOperatingSystemVersion',
          'MinorOperatingSystemVersion',
          'MajorImageVersion',
          'MinorImageVersion',
          'MajorSubsystemVersion',
          'MinorSubsystemVersion',
          'Reserved1',
          'SizeOfImage',
          'SizeOfHeaders',
          'CheckSum',
          'Subsystem',
          'DllCharacteristics',
          'SizeOfStackReserve',
          'SizeOfStackCommit',
          'SizeOfHeapReserve',
          'SizeOfHeapCommit',
          'LoaderFlags',
          'NumberOfRvaAndSizes']


def get_PEHeader_features(path):
    func_features = [0 for i in range(len(HEADER))]
    try:
        pe = pefile.PE(path)
    except:
        return func_features

    temp1 = dir(pe)
    if 'NT_HEADERS' in temp1:
        temp2 = dir(pe.NT_HEADERS)
        if 'OPTIONAL_HEADER' in temp2:
            for i in range(len(HEADER)):
                func_features[i] = getattr(pe.NT_HEADERS.OPTIONAL_HEADER, HEADER[i])
        else:
            return func_features
    else:
        return func_features

    print(path)
    return func_features


def scan_file(path):
    # scan a file to determine if it is malicious or benign
    if not os.path.exists("saved_detector.pkl"):
        print("It appears you haven't trained a detector yet!  Do this before scanning files.")
        sys.exit(1)
    with open("saved_detector.pkl", "rb") as saved_detector:
        classifier, hasher = pickle.load(saved_detector)
    features = get_PEHeader_features(path, hasher)
    result_proba = classifier.predict_proba([features])[:, 1]
    # if the user specifies malware_paths and benignware_paths, train a detector
    if result_proba > 0.5:
        print("It appears this file is malicious!", result_proba)
    else:
        print("It appears this file is benign.", result_proba)


def train_detector(benign_path, malicious_path, hasher):
    # train the detector on the specified training data
    def get_training_paths(directory):
        targets = []
        for path in os.listdir(directory):
            targets.append(os.path.join(directory, path))
        return targets

    malicious_paths = get_training_paths(malicious_path)
    benign_paths = get_training_paths(benign_path)
    print("Begin Training...")
    X = [get_PEHeader_features(path, hasher) for path in malicious_paths + benign_paths]
    y = [1 for i in range(len(malicious_paths))] + [0 for i in range(len(benign_paths))]
    classifier = RandomForestClassifier(64)
    classifier.fit(X, y)
    print("End Training...")
    print("Begin Saving Models...")
    pickle.dump((classifier, hasher), open("saved_detector.pkl", "wb+"))
    print("End Saving Models...")


def cv_evaluate(X, y, hasher):
    # use cross-validation to evaluate our model
    import random
    from sklearn import metrics
    from matplotlib import pyplot
    from sklearn.model_selection import KFold
    X, y = numpy.array(X), numpy.array(y)
    fold_counter = 0
    for train, test in KFold(2, shuffle=True).split(X, y):
        training_X, training_y = X[train], y[train]
        test_X, test_y = X[test], y[test]
        classifier = RandomForestClassifier(64)
        classifier.fit(training_X, training_y)
        scores = classifier.predict_proba(test_X)[:, -1]
        fpr, tpr, thresholds = metrics.roc_curve(test_y, scores)
        pyplot.semilogx(fpr, tpr, label="Fold number {0}".format(fold_counter))
        # pyplot.semilogx(fpr,tpr,label="ROC curve".format(fold_counter))
        fold_counter += 1
        with open("proba.log", "w") as f:
            scores.sort()
            for s in scores:
                f.write(str(s) + "\n")
    pyplot.xlabel("detector false positive rate")
    pyplot.ylabel("detector true positive rate")
    pyplot.title("Detector ROC curve")
    # pyplot.title("detector cross-validation ROC curves")
    pyplot.legend()
    pyplot.grid()
    pyplot.show()


def get_training_data(benign_path, malicious_path, hasher):
    def get_training_paths(directory):
        targets = []
        for path in os.listdir(directory):
            targets.append(os.path.join(directory, path))
        return targets

    malicious_paths = get_training_paths(malicious_path)
    benign_paths = get_training_paths(benign_path)
    X = [get_PEHeader_features(path, hasher) for path in malicious_paths + benign_paths]
    y = [1 for i in range(len(malicious_paths))] + [0 for i in range(len(benign_paths))]
    return X, y


def main():
    defaultpath = "./data"
    parser = argparse.ArgumentParser("get windows object vectors for files")
    parser.add_argument("--malware_paths", default=os.path.join(defaultpath, "malware"),
                        help="Path to malware training files")
    parser.add_argument("--benignware_paths", default=os.path.join(defaultpath, "benignware"),
                        help="Path to benignware training files")
    parser.add_argument("--scan_file_path", default=None, help="File to scan")
    parser.add_argument("--evaluate", default=False, action="store_true", help="Perform cross-validation")

    args = parser.parse_args()

    if args.scan_file_path:
        scan_file(args.scan_file_path)
    elif args.malware_paths and args.benignware_paths and not args.evaluate:
        train_detector(args.benignware_paths, args.malware_paths, hasher)
    elif args.malware_paths and args.benignware_paths and args.evaluate:
        X, y = get_training_data(args.benignware_paths, args.malware_paths, hasher)
        cv_evaluate(X, y, hasher)
    else:
        print("[*] You did not specify a path to scan," \
              " nor did you specify paths to malicious and benign training files" \
              " please specify one of these to use the detector.\n")
        parser.print_help()


if __name__ == '__main__':
    main()