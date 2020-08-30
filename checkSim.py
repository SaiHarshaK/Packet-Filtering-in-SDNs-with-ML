## @package checkSim
# Documentation for this module.
#
# This package consists all the necessary methods require to find similarity between
# requested webpage and filter words so that network administrator can decide how relevant the webpage is to the
# ones we wish to block

from bs4 import BeautifulSoup
import requests, urllib
import urllib3
from collections import Counter
import nltk
nltk.download('stopwords')
nltk.download('punkt')
import string
import re
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

from bert_embedding import BertEmbedding
import math
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
from random import random

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

## Method.
# @param keywords Set of keywords extracted for the url
# @return list of preprocessed keywords
#
# a preprocessing step for keywords like case lowering, remove punctuation,
# remove stopwords, and repititions as these negatively effect the ML method.
def preprocess(keywords):
  sentence = ' '.join(keywords)
  sentence = sentence.lower()
  sentence = re.sub(r'\d+', '', sentence)
  translator = str.maketrans('', '', string.punctuation)
  sentence = sentence.translate(translator)
  stop_words = set(stopwords.words("english"))
  word_tokens = word_tokenize(sentence)
  filtered_text = [word for word in word_tokens if word not in stop_words]
  raw_keywords =  Counter(filtered_text).most_common()
  return raw_keywords[:10]

## Method
# @param domain_name name of the domain of requested url
# @return list of keywords extracted for the given domain_name
#
# method to collect appropriate keywords for the requested url which form as input for the ML model to find similarity between requested page and filter words
def get_keywords(domain_name):
  # Send request and get webpage
  baseurl = "https://www.google.com/search?"
  params = {
    "q": domain_name
  }
  headers = {
    'User-Agent': 'Firefox/3.0.15'
  }
  url = baseurl + urllib.parse.urlencode(params)
  res = requests.get(url, headers=headers, verify=False)
  # fname = '/tmp/dbg' + str(random()) + '.html'
  # open(fname, 'wb').write(res.content)

  # Parse Beautiful Soup and get keywords
  soup = BeautifulSoup(res.text, features="html.parser")
  start = soup.get_text().find('ALL')
  end = min(soup.get_text().find(''.join([
        'In order to show you the most relevant results, we ',
        'have omitted some entries very similar to the 10 already displayed.']))%10000000,
      soup.get_text().find('Sign inSettingsPrivacyTerms')%10000000)
  keywords = soup.get_text()[start:end]

  # Return True if string is allowed. Basically eliminating all string that are bad
  def disallowed(string):
    # Do not allow empty strings
    if len(string) == 0:
      return False
    # Do not allow strings that are any combination of these letters ONLY
    if all(x in ['.', '|', '<', '>', '›', '-', '—', '_', '\n'] for x in list(set(string))):
      return False
    return True

  # Process every raw string - like eliminate new lines from them
  def process(string):
    return string.replace('\n', '')
  raw_keywords = list(filter(disallowed,  keywords.split(' ')[1:]))
  processed_keywords = map(process, raw_keywords)
  raw_keywords = preprocess(raw_keywords)
  # Result
  return raw_keywords

## Method
# @param keywords list of words of requested page after preprocessing is done
# @param filterwords list of appropriate words provided by the administrator based on requirement of which kind of websites need to be blocked
# @return float: similarity value
#
# this utility function where similarity between filterwords and keywords is found using the BERT embeddings of the words and finally return a similarity value between keywords and filterwords
def similarity_check_util(keywords,filterwords):
    bertembedding = BertEmbedding()
    avg_sim = []
    for filterword in filterwords:
      compare_value = bertembedding([filterword])[0][1][0]
      similarities = []
      for (word,count) in keywords:
          key_value = bertembedding([word])[0][1][0]
          similarity = np.dot(key_value,compare_value)/((math.sqrt(np.dot(key_value,key_value)))*(math.sqrt(np.dot(compare_value,compare_value))))
          similarities.append(similarity)
      avg_sim.append(np.max(similarities))
    return np.mean(avg_sim)

## Method
# @param servername name of the requested webpage
# @return similarity value [0,1] calculated by the model
#
# this is like a main function where required function calls are made to use the utility functions defined.
def similarity_check(servername):
  keywords = get_keywords(servername)
  ## List of some filter words to block pirated and torrent websites
  filterword = ['proxy','pirate','piracy','torrent', 'download']
  sim = similarity_check_util(keywords,filterword)
  print("\nSimilarity check on " + servername + ": " + str(sim) + "\n")
  return sim
