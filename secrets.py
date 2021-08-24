import os
import base64

from abc import ABC, abstractmethod
from functools import cached_property
from typing import Tuple, Type, Union, Callable


class BaseSecret(ABC):
  @abstractmethod
  def get_value(self):
    raise NotImplementedError

  @property
  def value(self):
    value = self.get_value()
    return value

  def __str__(self) -> str:
    return str(self.value)


class AWSSecretsManagerSecret(BaseSecret):
  def __init__(self, secret_id: str):
    self.secret_id: str = secret_id

    import boto3
    self.boto3 = boto3

  def get_value(self):
    response = self.client.get_secret_value(SecretId=self.secret_id)
    return response["SecretString"]

  @cached_property
  def client(self):
    return self.get_client()

  def get_client(self):
    return self.boto3.client("secretsmanager")


class EnvironmentVariable(BaseSecret):
  class Undefined(Exception):
    pass

  def __init__(self, name: str):
    self.name: str = name

  def get_value(self):
    value = os.getenv(self.name)
    if value is None:
      raise self.Undefined(self.name)
    return value


class Base64EncodedSecret(BaseSecret):
  def __init__(self, encoded: str):
    self.encoded: str = encoded

  def get_value(self):
    decoded = base64.b64decode(self.encoded)
    if isinstance(decoded, bytes):
      value = decoded.decode()
    else:
      value = decoded
    return value


class FileSystemSecret(BaseSecret):
  def __init__(self, path: str):
    self.path: str = path

  def get_value(self):
    with open(self.path, "r") as f:
      value = f.read()
    return value


class ChainedSecret(BaseSecret):
  def __init__(self, *secrets: BaseSecret):
    self.secrets: Tuple[Union[str, BaseSecret, Type[BaseSecret], Callable[[str], BaseSecret]]] = secrets

  def get_value(self):
    secrets = list(self.secret)
    secret = secrets.pop(0)
    if isinstance(secret, BaseSecret):
      value = secret.get_value()
    elif isinstance(secret, str):
      value = secret
    while secrets:
      secret = secrets.pop(0)
      if isinstance(secret, BaseSecret):
        value = secret.get_value()
      elif callable(secret):
        secret = secret(value)
        value = secret.get_value()
    return value


password = ChainedSecret(
  EnvironmentVariable("ADMIN_PASSWORD"),
  Base64EncodedSecret,
)
