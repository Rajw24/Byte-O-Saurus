print("Importing libraries")
import numpy as np
import pandas as pd 
import pefile
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.feature_selection import SelectFromModel
from sklearn.model_selection import train_test_split
from sklearn.datasets import load_iris
# print("Done Importing libraries")

#Read ata from csv
print("Reading csv")
malware_data = pd.read_csv("MalwareData.csv", sep="|")
iris = load_iris()
# print(pd.DataFrame(data=malware_data))
# for i in range(54):
#     print(f"{malware_data[0][i]} : {malware_data[1][i]}")
# print("Done Reading csv")

print("Filtering values")
#input values for training model
data_in = malware_data.drop(['Name', 'md5', 'legitimate'], axis=1).values
labels = malware_data['legitimate'].values
# print("Done Filtering values")

print("Implementing extra tree classifier and selecting data")
extra_trees = ExtraTreesClassifier().fit(data_in, labels) # type: ignore
selection = SelectFromModel(extra_trees, prefit=True)
# print("Done Implementing extra tree classifier and selecting data")
# print(f"Selection: {selection.get_support()}")

print("transforming selected data")
data_in_new = selection.transform(data_in)
legit_train, legit_test, mal_train, mal_test = train_test_split(data_in_new, labels, test_size=0.2)
# print("done transforming selected data")

print("Implementing random forest classifiers and fitting data")
classif = RandomForestClassifier(n_estimators=50)
classif.fit(legit_train, mal_train)
# print("Done Implementing random forest classifiers and fitting data")

# print(type(malware_data))
# print(type(data_in_new))
# print(data_in_new.ndim)
# print(data_in_new.shape)
# print(data_in_new.size)
# print(data_in_new.dtype)
# print(data_in_new[0])
# classgrad = GradientBoostingClassifier(n_estimators=50)
# classgrad.fit(legit_train, mal_train)

# classextra = ExtraTreesClassifier(n_estimators=50)
# classextra.fit(legit_train, mal_train)

print(f"The score of this model is: {classif.score(legit_test, mal_test) * 100}") # type: ignore
# print(f"The score of this model is: {classgrad.score(legit_test, mal_test) * 100}") # type: ignore
# print(f"The score of this model is: {classextra.score(legit_test, mal_test) * 100}") # type: ignore

# pe = pefile.PE("tally.exe")
# features = []
# features.append(pe.FILE_HEADER.Machine) # type: ignore
# features.append(pe.FILE_HEADER.SizeOfOptionalHeader) # type: ignore
# features.append(pe.FILE_HEADER.Characteristics) # type: ignore
# # features.append(pe.NT_HEADERS.ImageBase) # type: ignore
# # features.append(pe.NT_HEADERS.MajorOperatingSystemVersion) # type: ignore
# features.append(pe.NT_HEADERS.MajorSubsystemVersion) # type: ignore
# features.append(pe.NT_HEADERS.Subsystem) # type: ignore
# features.append(pe.NT_HEADERS.DllCharacteristics) # type: ignore
# features.append(pe.NT_HEADERS.SizeOfStackReserve) # type: ignore
# features.append(pe.OPTIONAL_HEADER.SizeOfCode) # type: ignore
# features = np.array(features).reshape(1,-1)
# print(features)

# prediction = classif.predict(features)

# if prediction[0] == 1:
#     print("Beware! it is a malware")
# else:
#     print("Relax! it is safe to use")

pe = pefile.PE("AnyDesk.exe")
features = []
try:
    features.append(pe.FILE_HEADER.Machine) # type: ignore
except:
    pass
print(features)
try:
    features.append(pe.FILE_HEADER.SizeOfOptionalHeader) # type: ignore
except:
    pass
print(features)
try:
    features.append(pe.FILE_HEADER.Characteristics) # type: ignore
except:
    pass
print(features)
try:
    features.append(pe.NT_HEADERS.ImageBase) # type: ignore
except:
    pass
print(features)
try:
    features.append(pe.NT_HEADERS.MajorOperatingSystemVersion) # type: ignore
except:
    pass
print(features)
try:
    features.append(pe.NT_HEADERS.MajorSubsystemVersion) # type: ignore
except:
    pass
print(features)
try:
    features.append(pe.NT_HEADERS.Subsystem) # type: ignore
except:
    pass
print(features)
try:
    features.append(pe.NT_HEADERS.DllCharacteristics) # type: ignore
except:
    pass
print(features)
try:
    features.append(pe.NT_HEADERS.SizeOfStackReserve) # type: ignore
except:
    pass
print(features)
try:
    features.append(pe.OPTIONAL_HEADER.SizeOfCode) # type: ignore
except:
    pass
print(features)
features = np.array(features).reshape(1,-1)
print(features)

prediction = classif.predict(features)

if prediction[0] == 1:
    print("Beware! it is a malware")
else:
    print("Relax! it is safe to use")