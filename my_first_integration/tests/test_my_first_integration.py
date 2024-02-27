
from app.my_first_integration import MyFirstIntegration
from app.model.request_body import RequestBody
from pykson import Pykson
import json
pykson = Pykson()
integration_class = MyFirstIntegration()

def test_addtowatchlist():
    req = '{"connectionParameters": {"username": "samplevalue", "password": "samplevalue", "serverurl": "samplevalue", "domain": "samplevalue"}, "parameters": {"addwatchlistname": "samplevalue", "containerdata": "samplevalue"}}'
    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.addtowatchlist(req)
    assert (resp is not None)

def test_createwatchlist():
    req = '{"connectionParameters": {"username": "samplevalue", "password": "samplevalue", "serverurl": "samplevalue", "domain": "samplevalue"}, "parameters": {"createwatchlistname": "samplevalue"}}'
    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.createwatchlist(req)
    assert (resp is not None)
