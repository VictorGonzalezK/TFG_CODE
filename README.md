# TFG_CODE
Code used in Analyse the usage of Machine Learning techniques in malicious URL classification<br>
Versions used can be found in requirements.txt<br>
The Training of the model is done in Jupyter Notebook ModelTraining.ipynb run on a conda enviroment<br>
The features extraction is done using:
  <li> SQL_Maneger.py to manage the inputs to the SQL Database (database connexion credentials have been deleted for privacy reasons)
  <li> FeatureExtraction.py to create functions that extract the features
  <li> And the remaining 5 files extract the URL from the file containing it extracted from diferent sources commented in the project, executes FeatureExtraction functions to extract data and saves it to the database.  
