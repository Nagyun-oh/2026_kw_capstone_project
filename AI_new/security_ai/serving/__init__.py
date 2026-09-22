"""Shared Transformer inference used by REST and Kafka transports."""

from .predictor import ModelRuntime

__all__ = ["ModelRuntime"]
