FROM python:3.13-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip wheel --no-cache-dir -w /wheels ".[fast]"

FROM python:3.13-slim
LABEL org.opencontainers.image.source=https://github.com/ChadiDridi/onprem-lb \
      org.opencontainers.image.description="On-demand, API-driven on-prem load balancer (L4 NLB + L7 ALB)" \
      org.opencontainers.image.licenses=Apache-2.0
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index /wheels/*.whl && rm -rf /wheels \
 && useradd --system --uid 10001 --no-create-home lb && mkdir -p /etc/onprem-lb /var/lib/onprem-lb \
 && chown lb /var/lib/onprem-lb
USER 10001
EXPOSE 9900
ENTRYPOINT ["onprem-lb"]
CMD ["serve", "-c", "/etc/onprem-lb/config.yaml", "--state-file", "/var/lib/onprem-lb/state.yaml"]
