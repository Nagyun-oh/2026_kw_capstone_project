from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

import torch
from torch import Tensor, nn

from .byte_tokenizer import FIELD_VOCAB_SIZE, PAD_ID, VOCAB_SIZE


@dataclass(frozen=True)
class HttpTransformerConfig:
    """Configuration for the first encoder-only binary HTTP classifier."""

    max_length: int = 1024
    hidden_size: int = 192
    num_layers: int = 4
    num_heads: int = 6
    ffn_size: int = 768
    dropout: float = 0.1
    classifier_hidden_size: int = 64
    structural_feature_size: int = 0
    structural_hidden_size: int = 32

    def __post_init__(self) -> None:
        if self.max_length < 8 or self.hidden_size < 1 or self.num_layers < 1:
            raise ValueError("max_length, hidden_size and num_layers must be positive")
        if self.hidden_size % self.num_heads:
            raise ValueError("hidden_size must be divisible by num_heads")
        if not 0 <= self.dropout < 1:
            raise ValueError("dropout must be in [0, 1)")
        if self.structural_feature_size < 0 or self.structural_hidden_size < 1:
            raise ValueError("structural feature sizes are invalid")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class HttpByteTransformer(nn.Module):
    """Bidirectional byte Transformer that emits one attack logit per request.

    Each position receives a byte/special-token embedding, an absolute position
    embedding, and an HTTP field embedding. The pre-LayerNorm encoder connects
    every visible byte to the full request context, and the binary head reads
    the contextual representation at the CLS position.
    """

    def __init__(self, config: HttpTransformerConfig) -> None:
        super().__init__()
        self.config = config
        self.token_embedding = nn.Embedding(VOCAB_SIZE, config.hidden_size, padding_idx=PAD_ID)
        self.position_embedding = nn.Embedding(config.max_length, config.hidden_size)
        self.field_embedding = nn.Embedding(FIELD_VOCAB_SIZE, config.hidden_size)
        self.embedding_norm = nn.LayerNorm(config.hidden_size)
        self.embedding_dropout = nn.Dropout(config.dropout)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=config.hidden_size,
            nhead=config.num_heads,
            dim_feedforward=config.ffn_size,
            dropout=config.dropout,
            activation="gelu",
            batch_first=True,
            norm_first=True,
        )
        self.encoder = nn.TransformerEncoder(
            encoder_layer,
            num_layers=config.num_layers,
            norm=nn.LayerNorm(config.hidden_size),
            enable_nested_tensor=False,
        )
        self.structural_projection: nn.Module | None = None
        classifier_input_size = config.hidden_size
        if config.structural_feature_size:
            self.structural_projection = nn.Sequential(
                nn.LayerNorm(config.structural_feature_size),
                nn.Linear(config.structural_feature_size, config.structural_hidden_size),
                nn.GELU(),
                nn.Dropout(config.dropout),
            )
            classifier_input_size += config.structural_hidden_size
        self.classifier = nn.Sequential(
            nn.Linear(classifier_input_size, config.classifier_hidden_size),
            nn.GELU(),
            nn.Dropout(config.dropout),
            nn.Linear(config.classifier_hidden_size, 1),
        )
        self._reset_embeddings()

    def _reset_embeddings(self) -> None:
        nn.init.normal_(self.token_embedding.weight, mean=0.0, std=0.02)
        with torch.no_grad():
            self.token_embedding.weight[PAD_ID].zero_()
        nn.init.normal_(self.position_embedding.weight, mean=0.0, std=0.02)
        nn.init.normal_(self.field_embedding.weight, mean=0.0, std=0.02)

    def forward(
        self,
        input_ids: Tensor,
        field_ids: Tensor,
        attention_mask: Tensor,
        structural_features: Tensor | None = None,
    ) -> Tensor:
        if input_ids.ndim != 2 or field_ids.shape != input_ids.shape:
            raise ValueError("input_ids and field_ids must have shape [batch, sequence]")
        if attention_mask.shape != input_ids.shape:
            raise ValueError("attention_mask shape must match input_ids")
        token_embeddings = self.token_embedding(input_ids)
        return self.forward_from_token_embeddings(
            token_embeddings, field_ids, attention_mask, structural_features
        )

    def forward_from_token_embeddings(
        self,
        token_embeddings: Tensor,
        field_ids: Tensor,
        attention_mask: Tensor,
        structural_features: Tensor | None = None,
    ) -> Tensor:
        """Run the encoder from token embeddings for attribution methods.

        Position and HTTP-field embeddings remain part of the model context.
        The public forward path and XAI path therefore share every layer after
        token lookup instead of maintaining two inference implementations.
        """

        if token_embeddings.ndim != 3 or token_embeddings.shape[:2] != field_ids.shape:
            raise ValueError("token_embeddings must have shape [batch, sequence, hidden]")
        if token_embeddings.shape[2] != self.config.hidden_size:
            raise ValueError("token embedding hidden dimension does not match model config")
        if attention_mask.shape != field_ids.shape:
            raise ValueError("attention_mask shape must match field_ids")
        sequence_length = token_embeddings.shape[1]
        if sequence_length > self.config.max_length:
            raise ValueError("input sequence exceeds configured max_length")
        positions = torch.arange(sequence_length, device=token_embeddings.device).unsqueeze(0)
        hidden = (
            token_embeddings
            + self.position_embedding(positions)
            + self.field_embedding(field_ids)
        )
        hidden = self.embedding_dropout(self.embedding_norm(hidden))
        encoded = self.encoder(hidden, src_key_padding_mask=~attention_mask.bool())
        pooled = encoded[:, 0]
        if self.structural_projection is not None:
            if structural_features is None:
                raise ValueError("structural_features are required by this model config")
            expected = (pooled.shape[0], self.config.structural_feature_size)
            if tuple(structural_features.shape) != expected:
                raise ValueError(f"structural_features must have shape {expected}")
            projected = self.structural_projection(structural_features)
            pooled = torch.cat((pooled, projected), dim=-1)
        return self.classifier(pooled).squeeze(-1)

    @property
    def parameter_count(self) -> int:
        return sum(parameter.numel() for parameter in self.parameters())
