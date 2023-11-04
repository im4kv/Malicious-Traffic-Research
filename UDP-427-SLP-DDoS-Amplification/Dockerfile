FROM python:3.10-alpine3.17

# Copy application files & Install packages
COPY docker/ /opt/dist/
RUN python3 -m pip install --no-cache-dir -r /opt/dist/requirements.txt && \
# Setup user, groups and configs
     addgroup --gid 2000 mtrapp && \
    adduser -D -u 2000 -G mtrapp mtrapp && \
    chown mtrapp:mtrapp -R /opt/dist

STOPSIGNAL SIGINT
USER mtrapp:mtrapp

WORKDIR /opt/dist

# Start Service
CMD ["python3","slp.py"]

