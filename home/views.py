import argparse

from django.shortcuts import render, redirect
import csv
from csv import writer
import os
import math
from django import template
import pandas as pd
import import_ipynb
from django.views.decorators.csrf import csrf_exempt

from home.Book_recommendation_model_2 import sim_distance, get_recommendations
from django.http import HttpResponse
from home.models import Cart, Interest
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from sklearn.metrics.pairwise import linear_kernel
from sklearn.feature_extraction.text import TfidfVectorizer
import requests
import gzip
import io
import soundfile as sf
from pydub import AudioSegment
import datetime
import binascii
import collections
import hashlib
import sys
import json
# pip install google-auth
from google.oauth2 import service_account
# pip install six
import six
from six.moves.urllib.parse import quote

register = template.Library()


@register.filter
def round_up(value):
    return int(math.floor(value))


def rated(userId, bookId):
    ratings = pd.read_csv(
        "/home/bhagyashreerao/PycharmProjects/Book-recommender-system/Django/BookRack/home/ratings.csv",
        engine="python")
    ratings = ratings[ratings["user_id"] == int(userId)]
    ratings = ratings.values.tolist()
    j = 0
    rat = 0
    flag = False
    for i in ratings:
        if i[1] == int(bookId):
            rat = ratings[j][2]
            rat = rat * 20
            flag = True
            break
        j = j + 1
    if flag:
        l = []
        l.append(flag)
        l.append(rat)
    else:
        l = []
        l.append(flag)
        l.append(0)
    return l


def giveRating(rating, userId, bookId):
    ratings = pd.read_csv(
        "/home/bhagyashreerao/PycharmProjects/Book-recommender-system/Django/BookRack/home/ratings.csv",
        engine="python")
    ratings = ratings[ratings["user_id"] == int(userId)]
    ratings = ratings.values.tolist()
    j = 0
    flag = False
    for i in ratings:
        if i[1] == int(bookId):
            flag = True
            break
    if not flag:
        row = [int(userId), int(bookId), rating]
        with open("/home/bhagyashreerao/PycharmProjects/Book-recommender-system/Django/BookRack/home/ratings.csv", 'a+',
                  newline='') as write_obj:
            csv_writer = writer(write_obj)
            csv_writer.writerow(row)


def recommend(bookid):
    book_description = pd.read_csv(
        "/home/bhagyashreerao/PycharmProjects/Book-recommender-system/Django/BookRack/home/book_data2.csv",
        engine="python")
    books_tfidf = TfidfVectorizer(stop_words='english')
    book_description['book_desc'] = book_description['book_desc'].fillna('')
    book_description_matrix = books_tfidf.fit_transform(book_description['book_desc'])
    # book_description_matrix.shape
    cosine_similarity = linear_kernel(book_description_matrix, book_description_matrix)
    similarity_scores = list(enumerate(cosine_similarity[bookid]))
    similarity_scores = sorted(similarity_scores, key=lambda x: x[1], reverse=True)
    similarity_scores = similarity_scores[1:6]
    books_index = [i[0] for i in similarity_scores]
    print(book_description['book_title'].iloc[books_index])
    viewdata = book_description.iloc[books_index].values.tolist()
    return viewdata



def audiobook(request):
    if 'loginuser' in request.session:
        print("iff")
        url = "https://asia-south1-exalted-point-310113.cloudfunctions.net/audiobookGenerator"
        param = {"name": "audiobooksample"}
        newHeaders = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        audioData = requests.post(url, json=param, headers=newHeaders)
        print(audioData.headers)
        print(audioData.content)

        url = generate_signed_url(
            service_account_file='/home/bhagyashreerao/PycharmProjects/Book-recommender-system/Django/BookRack/home/audiobookServiceAccountKey.json',
            http_method='GET', bucket_name='audiobookminiproject',
            object_name='audiobooksample.mp3')
        tag = '<a href = ' + url + '>'
        print(tag)
        return HttpResponse(url)


def product(request):
    return render(request, 'product.html')


def index(request, booktitle=None, bookauthor=None):
    print(request)
    if 'loginuser' in request.session:
        sameauth = {}
        data = {}
        rbooks = {}
        rbooks1 = []
        top1 = []
        mydata = pd.read_csv(
            "/home/bhagyashreerao/PycharmProjects/Book-recommender-system/Django/BookRack/home/book_data2.csv",
            engine="python")
        top = mydata.head(20)

        ratings = pd.read_csv(
            "/home/bhagyashreerao/PycharmProjects/Book-recommender-system/Django/BookRack/home/ratings.csv",
            engine="python")
        d = (ratings.groupby('user_id')['book_id', 'rating'].apply(lambda x: dict(x.values)).to_dict())
        print(len(d))
        uname = request.session["loginuser"]
        userId = request.session["userId"]
        print(userId)
        # user=User.objects.get_by_natural_key(username=uname)

        # print(userid)

        # data=Interest.objects.filter(userid=userid)

        # for book in data:
        #     rbooks += recommend(book.bookid)
        data = ratings[ratings["user_id"] == userId]
        print(data)

        popular = mydata.sort_values(by=['book_rating'], ascending=False)
        popular = popular.head(10)

        if data.empty:
            print("empty")
            top = top.values.tolist()
            top1.append(top)
            sameauth["auth"] = top1
        else:
            print("not empty")
            rec_books = get_recommendations(d, userId)
            print(rec_books)
            for i in range(10):
                book_id = rec_books[i][1]
                rbooks = mydata[mydata["book_id"] == book_id]
                rbooks = rbooks.values.tolist()
                rbooks1.append(rbooks)

            # print(rbooks1)
            sameauth["auth"] = rbooks1
        sameauth["auth2"] = popular.values.tolist()

        if 'viewbook' in request.POST:
            viewbookbtn = request.POST.get('viewbook')
            id = int(viewbookbtn)
            viewdata = mydata[mydata["book_id"] == id]
            avgrating = viewdata["book_rating"]
            avgrating = int(avgrating) * 20
            viewdata = viewdata.values.tolist()
            test = rated(1, id)

            # content based filtering
            book_description = pd.read_csv(
                "/home/bhagyashreerao/PycharmProjects/Book-recommender-system/Django/BookRack/home/book_data2.csv",
                encoding='latin-1')
            books_tfidf = TfidfVectorizer(stop_words='english')
            book_description['book_desc'] = book_description['book_desc'].fillna('')
            book_description_matrix = books_tfidf.fit_transform(book_description['book_desc'])
            cosine_similarity = linear_kernel(book_description_matrix, book_description_matrix)
            similarity_scores = list(enumerate(cosine_similarity[id - 1]))
            similarity_scores = sorted(similarity_scores, key=lambda x: x[1], reverse=True)
            similarity_scores = similarity_scores[1:6]
            books_index = [i[0] for i in similarity_scores]
            # print (book_description.iloc[books_index])
            viewdata1 = book_description.iloc[books_index].values.tolist()
            return render(request, 'product.html',
                          {'viewbook': viewdata, 'viewbook1': viewdata1, 'avgrating': avgrating, 'test': test})

        # for giving ratings
        if 'link' in request.POST:
            rating = request.POST.get('rating')
            bookId = request.POST.get('bookId')
            test = rated(userId, bookId)
            if not test[0]:
                test[0] = True
                test[1] = rating
                giveRating(rating, userId, bookId)
            id = int(bookId)
            viewdata = mydata[mydata["book_id"] == id]
            avgrating = viewdata["book_rating"]
            avgrating = int(avgrating) * 20
            viewdata = viewdata.values.tolist()
            test = rated(1, id)

            # content based filtering
            book_description = pd.read_csv(
                "/home/bhagyashreerao/PycharmProjects/Book-recommender-system/Django/BookRack/home/book_data2.csv",
                encoding='latin-1')
            books_tfidf = TfidfVectorizer(stop_words='english')
            book_description['book_desc'] = book_description['book_desc'].fillna('')
            book_description_matrix = books_tfidf.fit_transform(book_description['book_desc'])
            cosine_similarity = linear_kernel(book_description_matrix, book_description_matrix)
            similarity_scores = list(enumerate(cosine_similarity[id - 1]))
            similarity_scores = sorted(similarity_scores, key=lambda x: x[1], reverse=True)
            similarity_scores = similarity_scores[1:6]
            books_index = [i[0] for i in similarity_scores]
            # print (book_description.iloc[books_index])
            viewdata1 = book_description.iloc[books_index].values.tolist()
            return render(request, 'product.html',
                          {'viewbook': viewdata, 'viewbook1': viewdata1, 'avgrating': avgrating, 'test': test})

        # for search
        if 'sbutton' in request.POST:
            print(request.POST.get('stype'))
            viewdata1 = []
            if (request.POST.get('stype') == '0'):
                title = request.POST.get('searchbox')
                viewdata = mydata[mydata['book_title'] == title]
                viewdata = viewdata.values.tolist()
                print(viewdata)
                viewdata1.append(viewdata)
                book_description = pd.read_csv(
                    "/home/bhagyashreerao/PycharmProjects/Book-recommender-system/Django/BookRack/home/book_data2.csv",
                    encoding='latin-1')
                books_tfidf = TfidfVectorizer(stop_words='english')
                book_description['book_desc'] = book_description['book_desc'].fillna('')
                book_description_matrix = books_tfidf.fit_transform(book_description['book_desc'])
                cosine_similarity = linear_kernel(book_description_matrix, book_description_matrix)
                print(int(viewdata[0][0]))
                similarity_scores = list(enumerate(cosine_similarity[int(viewdata[0][0]) - 1]))
                similarity_scores = sorted(similarity_scores, key=lambda x: x[1], reverse=True)
                similarity_scores = similarity_scores[1:6]
                books_index = [i[0] for i in similarity_scores]
                # print (book_description.iloc[books_index])
                viewdata12 = book_description.iloc[books_index].values.tolist()
                viewdata1.append(viewdata12)
                sameauth['auth'] = viewdata1
            if (request.POST.get('stype') == '1'):
                author = request.POST.get('searchbox')
                viewdata = mydata[mydata['book_author'] == author]

                sameauth['auth'] = viewdata.values.tolist()
            return render(request, 'index.html', sameauth)

        return render(request, 'index.html', sameauth)
    else:
        return redirect('account/login')


def wishlist(request):
    if 'loginuser' in request.session:
        viewdata = {}
        viewdata1 = []
        uname = request.session["loginuser"]
        userId = request.session["userId"]
        ratings = pd.read_csv(
            "/home/bhagyashreerao/PycharmProjects/Book-recommender-system/Django/BookRack/home/ratings.csv",
            engine="python")
        books = pd.read_csv(
            "/home/bhagyashreerao/PycharmProjects/Book-recommender-system/Django/BookRack/home/book_data2.csv",
            encoding='latin-1')
        ratings = ratings[ratings["user_id"] == userId]
        for bookID in ratings["book_id"]:
            viewdata = books[books["book_id"] == bookID]
            viewdata = viewdata.values.tolist()
            viewdata1.append(viewdata)

        return render(request, 'wishlist.html', {'cartdisplay': viewdata1})
    else:
        return redirect('account/login')


def generate_signed_url(service_account_file, bucket_name, object_name,
                        subresource=None, expiration=604800, http_method='GET',
                        query_parameters=None, headers=None):
    if expiration > 604800:
        print('Expiration Time can\'t be longer than 604800 seconds (7 days).')
        sys.exit(1)

    escaped_object_name = quote(six.ensure_binary(object_name), safe=b'/~')
    canonical_uri = '/{}'.format(escaped_object_name)

    datetime_now = datetime.datetime.utcnow()
    request_timestamp = datetime_now.strftime('%Y%m%dT%H%M%SZ')
    datestamp = datetime_now.strftime('%Y%m%d')

    google_credentials = service_account.Credentials.from_service_account_file(
        service_account_file)
    client_email = google_credentials.service_account_email
    credential_scope = '{}/auto/storage/goog4_request'.format(datestamp)
    credential = '{}/{}'.format(client_email, credential_scope)

    if headers is None:
        headers = dict()
    host = '{}.storage.googleapis.com'.format(bucket_name)
    headers['host'] = host

    canonical_headers = ''
    ordered_headers = collections.OrderedDict(sorted(headers.items()))
    for k, v in ordered_headers.items():
        lower_k = str(k).lower()
        strip_v = str(v).lower()
        canonical_headers += '{}:{}\n'.format(lower_k, strip_v)

    signed_headers = ''
    for k, _ in ordered_headers.items():
        lower_k = str(k).lower()
        signed_headers += '{};'.format(lower_k)
    signed_headers = signed_headers[:-1]  # remove trailing ';'

    if query_parameters is None:
        query_parameters = dict()
    query_parameters['X-Goog-Algorithm'] = 'GOOG4-RSA-SHA256'
    query_parameters['X-Goog-Credential'] = credential
    query_parameters['X-Goog-Date'] = request_timestamp
    query_parameters['X-Goog-Expires'] = expiration
    query_parameters['X-Goog-SignedHeaders'] = signed_headers
    if subresource:
        query_parameters[subresource] = ''

    canonical_query_string = ''
    ordered_query_parameters = collections.OrderedDict(
        sorted(query_parameters.items()))
    for k, v in ordered_query_parameters.items():
        encoded_k = quote(str(k), safe='')
        encoded_v = quote(str(v), safe='')
        canonical_query_string += '{}={}&'.format(encoded_k, encoded_v)
    canonical_query_string = canonical_query_string[:-1]  # remove trailing '&'

    canonical_request = '\n'.join([http_method,
                                   canonical_uri,
                                   canonical_query_string,
                                   canonical_headers,
                                   signed_headers,
                                   'UNSIGNED-PAYLOAD'])

    canonical_request_hash = hashlib.sha256(
        canonical_request.encode()).hexdigest()

    string_to_sign = '\n'.join(['GOOG4-RSA-SHA256',
                                request_timestamp,
                                credential_scope,
                                canonical_request_hash])

    # signer.sign() signs using RSA-SHA256 with PKCS1v15 padding
    signature = binascii.hexlify(
        google_credentials.signer.sign(string_to_sign)
    ).decode()

    scheme_and_host = '{}://{}'.format('https', host)
    signed_url = '{}{}?{}&x-goog-signature={}'.format(
        scheme_and_host, canonical_uri, canonical_query_string, signature)

    return signed_url
