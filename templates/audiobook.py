import re
import json
import jenkspy
import pandas as pd
import numpy as np
from google.cloud import vision
from google.cloud import storage
from google.cloud import texttospeech
from google.protobuf import json_format
import datetime
import binascii
import collections
import hashlib
import sys

client = vision.ImageAnnotatorClient()
storage_client = storage.Client()
texttospeech_client = texttospeech.TextToSpeechClient()

bucket = storage_client.get_bucket('audiobookminiproject')


def gcs_audiobook_trigger(request):
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Content-Type': 'audio/mpeg'
    }
    # print("request",request)
    request_json = request.get_json(silent=True)
    request_args = request.args
    # print("json:",request_json)
    # print("args:",request_args)
    if request_json and 'name' in request_json:
        pdfName = request_json['name']
    elif request_args and 'name' in request_args:
        pdfName = request_args['name']
    else:
        return 'invalid'
    print(pdfName)
    audioName = pdfName + '.mp3'
    print(bucket)
    audioBlob = bucket.blob(audioName)
    print(audioBlob.exists())
    if audioBlob.exists():
        print("inside if")

        return (audioName, 200, headers)
    else:
        createAudiobook(pdfName)
        print("creating audiobook")
        while audioBlob.exists():
            if audioBlob.exists():
                audioBlob = bucket.get_blob(audioName)
                return (audioName, 200, headers)
    return (audioName, 200, headers)


def createAudiobook(pdfName):
    gcs_source_uri = "gs://{}/{}".format(bucket.name, pdfName + '.pdf')
    gcs_source = vision.GcsSource(uri=gcs_source_uri)
    input_config = vision.InputConfig(
        gcs_source=gcs_source, mime_type="application/pdf"
    )
    feature = vision.Feature(
        type_=vision.Feature.Type.DOCUMENT_TEXT_DETECTION)

    gcs_dest_uri = "gs://{}/{}".format(bucket.name, pdfName + ".")
    gcs_destination = vision.GcsDestination(uri=gcs_dest_uri)
    output_config = vision.OutputConfig(
        gcs_destination=gcs_destination, batch_size=100
    )
    async_request = vision.AsyncAnnotateFileRequest(
        features=[feature], input_config=input_config,
        output_config=output_config)

    operation = client.async_batch_annotate_files(
        requests=[async_request])

    print('Waiting for the operation to finish.')
    operation.result(timeout=420)
    jsonToText(gcs_dest_uri, pdfName)
    return


def jsonToText(gcs_dest_uri, pdfName):
    match = re.match(r'gs://([^/]+)/(.+)', gcs_dest_uri)
    prefix = match.group(2)
    blob_list = list(bucket.list_blobs(prefix=prefix))
    for n in range(len(blob_list)):
        output = blob_list[n]
        json_string = output.download_as_string()
        print(json_string)
        json_string = json_string.replace("u'", "'")
        response = vision.AnnotateFileResponse.from_json(json_string)
        # response = json_format.Parse(json_string, vision.AnnotateFileResponse())
        # response = json.loads(json_string)
        page_features = []
        for resp in response.responses:
            for page in resp.full_text_annotation.pages:
                # collect para features for the page
                for block in page.blocks:
                    for para in block.paragraphs:
                        f = extract_paragraph_feature(para)
                        page_features.append(f)
    print("json to text done")
    createBreaks(page_features, gcs_dest_uri, pdfName)
    return


def extract_paragraph_feature(para):
    # collect text
    text = ""
    for word in para.words:
        for symbol in word.symbols:
            text += symbol.text
            if symbol.property.detected_break.type_:
                break_type = symbol.property.detected_break.type_
                if str(break_type) == "BreakType.SPACE":
                    text += " "  # if the break is SPACE

    # remove double quotes
    text = text.replace('"', "")

    # remove URLs
    text = re.sub("https?://[\w/:%#\$&\?\(\)~\.=\+\-]+", "", text)

    # extract bounding box features
    x_list = []
    y_list = []
    for v in para.bounding_box.normalized_vertices:
        x_list.append(v.x)
        y_list.append(v.y)
    f = {}
    f["text"] = text
    f["height"] = max(y_list) - min(y_list)
    return f


def createBreaks(page_features, gcs_dest_uri, pdfName):
    df = pd.DataFrame(page_features)
    breaks = jenkspy.jenks_breaks(df['height'], nb_class=3)
    df['include'] = np.where(df['height'] >= breaks[1], "yes", "no")
    audio_text = ""
    for index, row in df.iterrows():
        if row['include'] == "yes":
            audio_text += row['text'] + "\n"
    print("breaks done")
    createAudiomp3(audio_text, gcs_dest_uri, pdfName)


def createAudiomp3(audio_text, gcs_dest_uri, pdfName):
    input_text = texttospeech.SynthesisInput(text=audio_text)
    # Note: the voice can also be specified by name.
    # Names of voices can be retrieved with client.list_voices().
    voice = texttospeech.VoiceSelectionParams(
        language_code="en-US",
        name="en-US-Standard-C",
        ssml_gender=texttospeech.SsmlVoiceGender.FEMALE,
    )
    audio_config = texttospeech.AudioConfig(
        audio_encoding=texttospeech.AudioEncoding.MP3
    )
    response = texttospeech_client.synthesize_speech(
        request={"input": input_text, "voice": voice, "audio_config": audio_config}
    )

    uploadAudioObject(response, gcs_dest_uri, pdfName)
    print("audio done")
    return


def uploadAudioObject(audioObject, gcs_dest_uri, pdfName):
    blob = bucket.blob(pdfName + ".mp3")
    blob.upload_from_string(audioObject.audio_content, content_type="audio/mpeg")
    print(blob, "upload done")