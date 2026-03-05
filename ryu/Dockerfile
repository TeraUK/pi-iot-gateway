FROM python:3.9-slim

# Install Ryu and pin eventlet to a compatible version.
# eventlet >= 0.35 breaks Ryu's monkey-patching.
# Pin setuptools to a version that still has easy_install.get_script_args, which Ryu's setup.py depends on.

RUN pip install --no-cache-dir \
    "setuptools==67.8.0" \
    "wheel" && \
    pip install --no-cache-dir \
    ryu==4.34 \
    eventlet==0.30.2 \
    requests

# Directory for custom Ryu applications
RUN mkdir -p /opt/ryu/apps
WORKDIR /opt/ryu

# Copy custom apps into the image
COPY apps/ /opt/ryu/apps/

# OpenFlow listener and REST API
EXPOSE 6653 8080

# Run Ryu with the specified application.
CMD ["ryu-manager", "--ofp-listen-host", "0.0.0.0", "--ofp-tcp-listen-port", "6653", "/opt/ryu/apps/minimal_l2_switch.py"]
