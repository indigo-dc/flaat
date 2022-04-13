from pytest_cases import parametrize_with_cases
import flaat.flask.flask_test_cases as cases


@parametrize_with_cases("path, headers", cases=cases.Authorized)
def test_is_authorized(client, path, headers):
    response = client.get(path, headers=headers)
    assert response.status_code == 200


@parametrize_with_cases("path, headers", cases=cases.Unauthorized)
def test_not_authorized(client, path, headers):
    response = client.get(path, headers=headers)
    assert response.status_code == 401
