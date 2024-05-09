# Network Traffic and Client Interaction Inference in Video Teleconferencing
This repository contains the code and data for the project titled "Network Traffic and Client Interaction Inference in 
Video Teleconferencing" for DSCI559: Machine Learning for a Secure Internet.

## This repository contains the following files:
1. `README.md`: This file.
2. `data/`: This directory contains the data used in the project.
   - `datasets.db`: This SQLite database contains the URLs and metadata of the datasets used in the project. 
   - `pcap_files/`: This directory contains the pcap files used in the project.
   - `csv_files/`: This directory contains the csv files that were generated from the pcap files.
   - `pickle_files/`: This directory contains the pickle files that contains preprocessed data for the models.
   - `samples/`: This directory contains the samples of the data used for exploratory data analysis and sever-client architecture analysis.
3. `notebook/`: This directory contains the Jupyter notebooks used in the project.
   - `network_graph.ipynb`: 1st part of the analysis where we analyze the server-client architecture of the video teleconferencing applications.
   - `feature_selection.ipynb`: Feature selection and EDA for the Bayesian Network.
   - `bayesian_networks.ipynb`: 2nd part of the analysis where we build a Bayesian Network to infer the client interaction from the network traffic.
4. `pcap_to_csv.py`: This script converts the pcap files to csv files.
5. `preprocessing.py`: This script preprocesses the csv files for Bayesian networks.

## Dataset
As some of the datasets used in the project are large, they are not included in the repository. 
The datasets can be downloaded from the following link:
- [Google Drive](https://drive.google.com/drive/folders/1LIxrSMvAa7thXScoUslBI4OU0yJt2FfW?usp=sharing)

Note: The datasets are from the following sources:
[DARPA SEARCHLIGHT Dataset](https://mergetb.org/projects/searchlight/dataset/)